import AppKit
import Foundation
import Vision
import CoreGraphics

struct WindowCandidate {
    let windowID: Int
    let owner: String
    let name: String
    let layer: Int
    let alpha: Double
    let sharingState: Int
    let x: Double
    let y: Double
    let width: Double
    let height: Double
}

let expectedActivityWidth = 647.0
let expectedActivityHeight = 498.0
let activityBottomTrimRatio = 0.05
let activityBottomTrimMaxPoints = 24.0

func runAppleScript(_ script: String) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    process.arguments = ["-e", script]

    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = Pipe()

    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        return nil
    }

    guard process.terminationStatus == 0 else {
        return nil
    }

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
}

func activityWindowTitle() -> String? {
    let script = #"tell application "System Events" to tell process "Cisco Packet Tracer" to get name of windows"#
    guard let output = runAppleScript(script), !output.isEmpty else {
        return nil
    }

    let titles = output.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
    return titles.first { $0.hasPrefix("PT Activity:") }
}

func parseBounds(_ window: [String: Any]) -> (Double, Double, Double, Double)? {
    guard let bounds = window[kCGWindowBounds as String] as? [String: Any],
          let x = bounds["X"] as? Double,
          let y = bounds["Y"] as? Double,
          let width = bounds["Width"] as? Double,
          let height = bounds["Height"] as? Double else {
        return nil
    }
    return (x, y, width, height)
}

func packetTracerCandidates() -> [WindowCandidate] {
    let windows = CGWindowListCopyWindowInfo([.optionAll, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
    return windows.compactMap { window in
        let owner = (window[kCGWindowOwnerName as String] as? String) ?? ""
        guard owner == "Cisco Packet Tracer" else {
            return nil
        }

        let name = (window[kCGWindowName as String] as? String) ?? ""
        let layer = window[kCGWindowLayer as String] as? Int ?? -1
        let alpha = window[kCGWindowAlpha as String] as? Double ?? 0.0
        let sharingState = window[kCGWindowSharingState as String] as? Int ?? -1
        guard let (x, y, width, height) = parseBounds(window) else {
            return nil
        }
        let windowID = window[kCGWindowNumber as String] as? Int ?? -1
        return WindowCandidate(
            windowID: windowID,
            owner: owner,
            name: name,
            layer: layer,
            alpha: alpha,
            sharingState: sharingState,
            x: x,
            y: y,
            width: width,
            height: height
        )
    }
}

func findActivityWindowID() -> Int? {
    if let targetTitle = activityWindowTitle() {
        let deadline = Date().addingTimeInterval(3.0)
        while Date() < deadline {
            let windows = packetTracerCandidates()
            if let match = windows.first(where: { $0.name == targetTitle }) {
                return match.windowID
            }
            usleep(150_000)
        }
    }

    let candidates = packetTracerCandidates()

    for candidate in candidates {
        if candidate.name.lowercased().contains("pt activity") {
            return candidate.windowID
        }
    }

    let fallback = candidates
        .filter { candidate in
            candidate.layer == 0
                && candidate.alpha > 0.0
                && !candidate.name.lowercased().contains("please wait")
                && candidate.width >= 450.0
                && candidate.width <= 900.0
                && candidate.height >= 300.0
                && candidate.height <= 700.0
        }
        .min { lhs, rhs in
            let lhsAspect = lhs.width / lhs.height
            let rhsAspect = rhs.width / rhs.height
            let lhsScore = abs(lhs.width - expectedActivityWidth) + abs(lhs.height - expectedActivityHeight) + abs(lhsAspect - (expectedActivityWidth / expectedActivityHeight)) * 120.0
            let rhsScore = abs(rhs.width - expectedActivityWidth) + abs(rhs.height - expectedActivityHeight) + abs(rhsAspect - (expectedActivityWidth / expectedActivityHeight)) * 120.0
            return lhsScore < rhsScore
        }

    if let fallback {
        return fallback.windowID
    }

    return nil
}

func describeCandidateWindows() -> [String] {
    return packetTracerCandidates().map { candidate in
        "pid=\(candidate.windowID) layer=\(candidate.layer) alpha=\(candidate.alpha) share=\(candidate.sharingState) owner=\(candidate.owner) name=\(candidate.name) pos=\(Int(candidate.x)),\(Int(candidate.y)) size=\(Int(candidate.width))x\(Int(candidate.height))"
    }
}

func windowBounds(windowID: Int) -> WindowCandidate? {
    return packetTracerCandidates().first { $0.windowID == windowID }
}

func cropActivityImage(at path: String, windowHeightPoints: Double) throws {
    guard let image = NSImage(contentsOfFile: path),
          let tiff = image.tiffRepresentation,
          let rep = NSBitmapImageRep(data: tiff),
          let cgImage = rep.cgImage else {
        throw NSError(domain: "packet_tracer_helpers", code: 2, userInfo: [NSLocalizedDescriptionKey: "Unable to load image at \(path)"])
    }

    guard windowHeightPoints > 0 else {
        throw NSError(domain: "packet_tracer_helpers", code: 3, userInfo: [NSLocalizedDescriptionKey: "Window height must be greater than zero"])
    }

    let imageWidth = cgImage.width
    let imageHeight = cgImage.height
    let cropHeightPoints = min(windowHeightPoints, expectedActivityHeight)
    let bottomTrimPoints = min(
        activityBottomTrimMaxPoints,
        max(0.0, cropHeightPoints * activityBottomTrimRatio)
    )
    let tightenedCropHeightPoints = max(1.0, cropHeightPoints - bottomTrimPoints)
    let scale = Double(imageHeight) / windowHeightPoints
    let cropHeightPixels = min(imageHeight, max(1, Int(round(tightenedCropHeightPoints * scale))))

    if cropHeightPixels >= imageHeight {
        return
    }

    let cropRect = CGRect(
        x: 0,
        y: imageHeight - cropHeightPixels,
        width: imageWidth,
        height: cropHeightPixels
    )

    guard let cropped = cgImage.cropping(to: cropRect) else {
        throw NSError(domain: "packet_tracer_helpers", code: 4, userInfo: [NSLocalizedDescriptionKey: "Unable to crop image at \(path)"])
    }

    let outputRep = NSBitmapImageRep(cgImage: cropped)
    guard let pngData = outputRep.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "packet_tracer_helpers", code: 5, userInfo: [NSLocalizedDescriptionKey: "Unable to encode cropped image at \(path)"])
    }

    try pngData.write(to: URL(fileURLWithPath: path))
}

func recognizeText(at path: String) throws -> [String] {
    guard let image = NSImage(contentsOfFile: path),
          let tiff = image.tiffRepresentation,
          let rep = NSBitmapImageRep(data: tiff),
          let cgImage = rep.cgImage else {
        throw NSError(domain: "packet_tracer_helpers", code: 1, userInfo: [NSLocalizedDescriptionKey: "Unable to load image at \(path)"])
    }

    let request = VNRecognizeTextRequest()
    request.recognitionLevel = .accurate
    request.usesLanguageCorrection = false
    request.recognitionLanguages = ["en-US", "de-DE"]

    let handler = VNImageRequestHandler(cgImage: cgImage)
    try handler.perform([request])

    let observations = request.results ?? []
    let sorted = observations.sorted {
        let ay = $0.boundingBox.midY
        let by = $1.boundingBox.midY
        if abs(ay - by) > 0.01 {
            return ay > by
        }
        return $0.boundingBox.minX < $1.boundingBox.minX
    }

    return sorted.compactMap { $0.topCandidates(1).first?.string }
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    fputs("usage: packet_tracer_helpers <window-id|window-bounds|window-debug|crop-activity|ocr> [args]\n", stderr)
    exit(2)
}

switch args[1] {
case "window-id":
    if let id = findActivityWindowID() {
        print(id)
        exit(0)
    }
    exit(3)

case "window-debug":
    for line in describeCandidateWindows() {
        print(line)
    }
    exit(0)

case "window-bounds":
    guard args.count >= 3, let requestedID = Int(args[2]) else {
        fputs("usage: packet_tracer_helpers window-bounds <window_id>\n", stderr)
        exit(2)
    }
    if let candidate = windowBounds(windowID: requestedID) {
        print("\(Int(candidate.x)) \(Int(candidate.y)) \(Int(candidate.width)) \(Int(candidate.height))")
        exit(0)
    }
    exit(3)

case "crop-activity":
    guard args.count >= 4, let windowHeightPoints = Double(args[3]) else {
        fputs("usage: packet_tracer_helpers crop-activity <image_path> <window_height_points>\n", stderr)
        exit(2)
    }

    do {
        try cropActivityImage(at: args[2], windowHeightPoints: windowHeightPoints)
        exit(0)
    } catch {
        fputs("\(error)\n", stderr)
        exit(1)
    }

case "ocr":
    guard args.count >= 3 else {
        fputs("usage: packet_tracer_helpers ocr <image_path>\n", stderr)
        exit(2)
    }

    do {
        for line in try recognizeText(at: args[2]) {
            print(line)
        }
        exit(0)
    } catch {
        fputs("\(error)\n", stderr)
        exit(1)
    }

default:
    fputs("unknown command: \(args[1])\n", stderr)
    exit(2)
}
