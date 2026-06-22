#!/usr/bin/env python3
import csv
import argparse
import logging
import os
import re
import shlex
import subprocess
import sys
import time
import unicodedata
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence, Tuple


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_PT_APP = "/Applications/Cisco Packet Tracer 9.0.0/Cisco Packet Tracer 9.0.app"
HELPER_SRC = BASE_DIR / "packet_tracer_helpers.swift"
HELPER_BIN = Path("/tmp/packet_tracer_helpers")
DEFAULT_ACTIVITY_WINDOW_TIMEOUT = 300.0
DEFAULT_PACKET_TRACER_EXIT_TIMEOUT = 20.0
DEFAULT_OCR_TIMEOUT = 20.0
DEFAULT_CAPTURE_OCR_TIMEOUT = 30.0
WINDOW_DEBUG_DUMP_INTERVAL = 10.0
SUBMISSION_RETRY_COUNT = 2
CSV_BASE_HEADER = ["Name des Studenten", "filename", "completition", "instructor_use_only"]
CSV_HEADER = CSV_BASE_HEADER + ["duplicate_instructor_use_only"]
PACKET_TRACER_MATCHES = (
    "packet tracer",
    "packettracer",
    "cisco%20packet%20tracer",
)

DEFAULT_ROOT_PREFIX = "240304-Abgabe Packet Tracer HUE ITSB-B"
PT_APP = DEFAULT_PT_APP
ROOT_PREFIX = DEFAULT_ROOT_PREFIX
ACTIVITY_WINDOW_TIMEOUT = DEFAULT_ACTIVITY_WINDOW_TIMEOUT
PACKET_TRACER_EXIT_TIMEOUT = DEFAULT_PACKET_TRACER_EXIT_TIMEOUT
OCR_TIMEOUT = DEFAULT_OCR_TIMEOUT
CAPTURE_OCR_TIMEOUT = DEFAULT_CAPTURE_OCR_TIMEOUT
LOGGER = logging.getLogger("packet_tracer")
DEBUG_MODE = False
DEBUG_LOG_FILE: Optional[Path] = None


class PacketTracerDiagnosticError(RuntimeError):
    category = "Processing failure"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    def describe(self) -> str:
        return f"{self.category}: {self.message}"


class ActivityWindowNotFoundError(PacketTracerDiagnosticError):
    category = "Activity window not found"


class ScreenshotCaptureError(PacketTracerDiagnosticError):
    category = "Screenshot empty or unusable"


class OCRFailureError(PacketTracerDiagnosticError):
    category = "OCR failed"


class OCRParseError(PacketTracerDiagnosticError):
    category = "OCR returned text, but the parser found no usable match"


class InstructorMissingError(PacketTracerDiagnosticError):
    category = "Completion recognized, but instructor metadata missing"


class WrongWindowCaptureError(PacketTracerDiagnosticError):
    category = "Wrong window capture suspected"


def setup_logging(debug: bool, log_file: Optional[Path]) -> Optional[Path]:
    global DEBUG_MODE, DEBUG_LOG_FILE

    DEBUG_MODE = debug
    if not debug:
        DEBUG_LOG_FILE = None
        return None

    if log_file is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        log_file = Path.cwd() / f"packet-tracer-debug-{stamp}.log"

    log_file = log_file.expanduser().resolve()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    LOGGER.handlers.clear()
    LOGGER.setLevel(logging.DEBUG)
    LOGGER.propagate = False

    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    LOGGER.addHandler(handler)

    DEBUG_LOG_FILE = log_file
    LOGGER.debug("=== packet-tracer debug session start ===")
    LOGGER.debug("cwd=%s", Path.cwd())
    LOGGER.debug("argv=%s", sys.argv)
    LOGGER.debug("python_executable=%s", sys.executable)
    LOGGER.debug("python_version=%s", sys.version.replace("\n", " "))
    LOGGER.debug("platform=%s", sys.platform)
    LOGGER.debug("base_dir=%s", BASE_DIR)
    LOGGER.debug("packet_tracer_app=%s", PT_APP)
    LOGGER.debug("root_prefix=%s", ROOT_PREFIX)
    LOGGER.debug("activity_window_timeout=%s", ACTIVITY_WINDOW_TIMEOUT)
    LOGGER.debug("packet_tracer_exit_timeout=%s", PACKET_TRACER_EXIT_TIMEOUT)
    LOGGER.debug("ocr_timeout=%s", OCR_TIMEOUT)
    LOGGER.debug("capture_ocr_timeout=%s", CAPTURE_OCR_TIMEOUT)
    LOGGER.debug("log_file=%s", log_file)
    return log_file


def run(cmd, *, check=True, capture_output=False, text=False, input=None):
    if DEBUG_MODE and not capture_output:
        capture_output = True

    command_text = shlex.join(str(part) for part in cmd)
    if DEBUG_MODE:
        LOGGER.debug("RUN %s", command_text)

    result = subprocess.run(
        cmd,
        check=check,
        capture_output=capture_output,
        text=text,
        input=input,
    )

    if DEBUG_MODE:
        LOGGER.debug("EXIT %s rc=%s", command_text, result.returncode)
        stdout = getattr(result, "stdout", None)
        stderr = getattr(result, "stderr", None)
        if stdout:
            LOGGER.debug("STDOUT %s\n%s", command_text, stdout.rstrip())
        if stderr:
            LOGGER.debug("STDERR %s\n%s", command_text, stderr.rstrip())

    return result


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from exc

    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"value must be greater than zero: {value!r}")
    return parsed


def resolve_string_setting(cli_value: Optional[str], env_name: str, default: str) -> str:
    if cli_value:
        return cli_value

    env_value = os.environ.get(env_name)
    if env_value:
        return env_value

    return default


def resolve_float_setting(cli_value: Optional[float], env_name: str, default: float) -> float:
    if cli_value is not None:
        return cli_value

    env_value = os.environ.get(env_name)
    if env_value is None or not env_value.strip():
        return default

    try:
        parsed = float(env_value)
    except ValueError as exc:
        raise ValueError(
            f"environment variable {env_name} must be a number, got {env_value!r}"
        ) from exc

    if parsed <= 0:
        raise ValueError(
            f"environment variable {env_name} must be greater than zero, got {env_value!r}"
        )

    return parsed


def apply_runtime_config(args: argparse.Namespace) -> None:
    global PT_APP, ROOT_PREFIX
    global ACTIVITY_WINDOW_TIMEOUT, PACKET_TRACER_EXIT_TIMEOUT
    global OCR_TIMEOUT, CAPTURE_OCR_TIMEOUT

    cli_app = str(args.packet_tracer_app.expanduser()) if args.packet_tracer_app else None
    PT_APP = resolve_string_setting(cli_app, "PACKET_TRACER_APP", DEFAULT_PT_APP)
    ROOT_PREFIX = resolve_string_setting(args.root_prefix, "PACKET_TRACER_ROOT_PREFIX", DEFAULT_ROOT_PREFIX)
    ACTIVITY_WINDOW_TIMEOUT = resolve_float_setting(
        args.activity_window_timeout,
        "PACKET_TRACER_ACTIVITY_WINDOW_TIMEOUT",
        DEFAULT_ACTIVITY_WINDOW_TIMEOUT,
    )
    PACKET_TRACER_EXIT_TIMEOUT = resolve_float_setting(
        args.packet_tracer_exit_timeout,
        "PACKET_TRACER_EXIT_TIMEOUT",
        DEFAULT_PACKET_TRACER_EXIT_TIMEOUT,
    )
    OCR_TIMEOUT = resolve_float_setting(
        args.ocr_timeout,
        "PACKET_TRACER_OCR_TIMEOUT",
        DEFAULT_OCR_TIMEOUT,
    )
    CAPTURE_OCR_TIMEOUT = resolve_float_setting(
        args.capture_ocr_timeout,
        "PACKET_TRACER_CAPTURE_OCR_TIMEOUT",
        DEFAULT_CAPTURE_OCR_TIMEOUT,
    )


def describe_exception(exc: BaseException) -> str:
    if isinstance(exc, PacketTracerDiagnosticError):
        return exc.describe()
    return str(exc) or exc.__class__.__name__


def compile_helper() -> None:
    if HELPER_BIN.exists() and HELPER_BIN.stat().st_mtime >= HELPER_SRC.stat().st_mtime:
        return

    cmd = [
        "swiftc",
        "-O",
        "-framework",
        "AppKit",
        "-framework",
        "Vision",
        "-framework",
        "CoreGraphics",
        str(HELPER_SRC),
        "-o",
        str(HELPER_BIN),
    ]
    run(cmd)


def helper_window_id() -> Optional[int]:
    result = run([str(HELPER_BIN), "window-id"], capture_output=True, text=True, check=False)
    if result.returncode == 0:
        out = result.stdout.strip()
        if DEBUG_MODE:
            LOGGER.debug("helper_window_id=%s", out or None)
        return int(out) if out else None
    if result.returncode == 3:
        if DEBUG_MODE:
            LOGGER.debug("helper_window_id not found")
        return None
    raise ActivityWindowNotFoundError(
        result.stderr.strip() or "window-id helper failed unexpectedly"
    )


def helper_window_debug() -> None:
    result = run([str(HELPER_BIN), "window-debug"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        if DEBUG_MODE:
            LOGGER.debug("helper_window_debug rc=%s", result.returncode)
        return

    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if DEBUG_MODE:
        if lines:
            LOGGER.debug("window_candidates=%s", lines)
        else:
            LOGGER.debug("window_candidates=[]")


def helper_window_bounds(window_id: int) -> Optional[Tuple[int, int, int, int]]:
    result = run(
        [str(HELPER_BIN), "window-bounds", str(window_id)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        parts = result.stdout.strip().split()
        if len(parts) == 4:
            return tuple(int(part) for part in parts)  # type: ignore[return-value]
    if result.returncode == 3:
        return None
    raise ScreenshotCaptureError(result.stderr.strip() or f"window-bounds failed for window {window_id}")


def helper_ocr(image_path: Path) -> List[str]:
    if not image_path.exists():
        raise ScreenshotCaptureError(f"screenshot file not found: {image_path}")

    if image_path.stat().st_size == 0:
        raise ScreenshotCaptureError(f"screenshot file is empty: {image_path}")

    result = run(
        [str(HELPER_BIN), "ocr", str(image_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise OCRFailureError(result.stderr.strip() or "ocr helper failed")
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if DEBUG_MODE:
        LOGGER.debug("ocr_image=%s", image_path)
        for idx, line in enumerate(lines, start=1):
            LOGGER.debug("ocr_line[%s]=%s", idx, line)
    return lines


def list_packet_tracer_processes() -> List[Tuple[int, str]]:
    result = subprocess.run(
        ["ps", "-ef"],
        check=False,
        capture_output=True,
        text=True,
    )
    matches: List[Tuple[int, str]] = []
    skip_pids = {os.getpid(), os.getppid()}

    for line in result.stdout.splitlines():
        lower = line.lower()
        if not any(token in lower for token in PACKET_TRACER_MATCHES) and "PacketTracer" not in line:
            continue

        parts = line.split(None, 7)
        if len(parts) < 2:
            continue

        try:
            pid = int(parts[1])
        except ValueError:
            continue

        if pid in skip_pids:
            continue

        matches.append((pid, line.strip()))

    return matches


def kill_packet_tracer() -> None:
    processes = list_packet_tracer_processes()
    killed: List[int] = []
    if DEBUG_MODE and processes:
        LOGGER.debug(
            "matched_packet_tracer_processes=%s",
            [line for _, line in processes],
        )

    for pid, _ in processes:
        try:
            os.kill(pid, 9)
            killed.append(pid)
        except ProcessLookupError:
            continue
        except PermissionError:
            if DEBUG_MODE:
                LOGGER.exception("failed_to_kill_pid=%s", pid)

    if DEBUG_MODE and killed:
        LOGGER.debug("killed_packet_tracer_pids=%s", killed)


def wait_for_packet_tracer_exit(timeout: Optional[float] = None) -> None:
    effective_timeout = PACKET_TRACER_EXIT_TIMEOUT if timeout is None else timeout
    deadline = time.time() + effective_timeout
    while time.time() < deadline:
        processes = list_packet_tracer_processes()
        if not processes:
            return
        if DEBUG_MODE:
            LOGGER.debug(
                "waiting_for_packet_tracer_exit active_pids=%s",
                [pid for pid, _ in processes],
            )
        time.sleep(0.5)


def safe_stem(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")


def discover_roots(base_dir: Path) -> List[Path]:
    roots = [
        entry
        for entry in base_dir.iterdir()
        if entry.is_dir() and entry.name.startswith(ROOT_PREFIX)
    ]
    return sorted(roots, key=lambda path: path.name)


def expand_requested_roots(requested_roots: Sequence[Path]) -> List[Path]:
    expanded: List[Path] = []
    seen: set[Path] = set()

    for requested_root in requested_roots:
        root = requested_root.expanduser().resolve()
        if not root.exists() or not root.is_dir():
            continue

        if any(root.glob("*.pka")):
            candidates = [root]
        else:
            discovered = discover_roots(root)
            candidates = discovered if discovered else [root]

        for candidate in candidates:
            candidate = candidate.resolve()
            if candidate in seen:
                continue
            seen.add(candidate)
            expanded.append(candidate)

    return expanded


def student_name_from_path(pka_path: Path) -> str:
    folder = pka_path.parent.name
    suffix = "_assignsubmission_file"
    if folder.endswith(suffix):
        prefix = folder[: -len(suffix)]
        if "_" in prefix:
            return prefix.rsplit("_", 1)[0]
    return folder


def csv_key(student_name: str, filename: str) -> Tuple[str, str]:
    return student_name, filename


def candidate_csv_paths(root: Path) -> List[Path]:
    return sorted(
        path
        for path in root.iterdir()
        if path.is_file() and path.suffix.lower() == ".csv"
    )


def csv_has_expected_header(csv_path: Path) -> bool:
    try:
        with csv_path.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.reader(fh, delimiter=";")
            first_row = next(reader, None)
    except Exception:
        return False
    return first_row is not None and first_row[:4] == CSV_BASE_HEADER


def resolve_csv_path(root: Path) -> Path:
    default_path = root / "completion.csv"
    if default_path.exists():
        return default_path

    csv_paths = [path for path in candidate_csv_paths(root) if csv_has_expected_header(path)]
    if len(csv_paths) == 1:
        return csv_paths[0]

    return default_path


def read_existing_csv_rows(csv_path: Path) -> dict[Tuple[str, str], List[str]]:
    rows: dict[Tuple[str, str], List[str]] = {}
    if not csv_path.exists():
        return rows

    with csv_path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh, delimiter=";")
        for row_index, row in enumerate(reader):
            if row_index == 0 and row[:4] == CSV_BASE_HEADER:
                continue
            if len(row) < 4:
                continue
            student, filename, completion, instructor = row[:4]
            rows[csv_key(student, filename)] = [student, filename, completion, instructor]
    return rows


def annotate_duplicate_instructors(rows: Sequence[List[str]]) -> List[List[str]]:
    counts: dict[str, int] = {}
    for row in rows:
        if len(row) < 4:
            continue
        instructor = row[3].strip()
        if not instructor:
            continue
        counts[instructor] = counts.get(instructor, 0) + 1

    annotated_rows: List[List[str]] = []
    for row in rows:
        base_row = list(row[:4])
        instructor = base_row[3].strip() if len(base_row) >= 4 else ""
        duplicate_flag = "yes" if instructor and counts.get(instructor, 0) > 1 else ""
        annotated_rows.append(base_row + [duplicate_flag])
    return annotated_rows


def write_csv_rows(csv_path: Path, rows: Sequence[List[str]]) -> None:
    annotated_rows = annotate_duplicate_instructors(rows)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, delimiter=";")
        writer.writerow(CSV_HEADER)
        for row in annotated_rows:
            writer.writerow(row)


def expected_screenshot_path(pka_path: Path, pka_files_in_folder: Sequence[Path]) -> Path:
    folder = pka_path.parent
    screenshot_name = screenshot_name_for_folder(list(pka_files_in_folder), pka_path)
    screenshot_path = folder / screenshot_name
    legacy_path = folder / legacy_screenshot_name_for_folder(list(pka_files_in_folder), pka_path)

    if screenshot_path != legacy_path and not screenshot_path.exists() and legacy_path.exists():
        legacy_path.rename(screenshot_path)
        if DEBUG_MODE:
            LOGGER.debug("renamed_legacy_screenshot old=%s new=%s", legacy_path, screenshot_path)

    return screenshot_path


def row_is_complete(row: Optional[List[str]]) -> bool:
    if not row:
        return False
    return bool(row[2].strip() and row[3].strip())


def open_pka_in_packet_tracer(pka_path: Path, attempt: int = 1) -> None:
    if attempt <= 1:
        commands = [
            ["open", "-a", PT_APP, str(pka_path)],
            ["open", str(pka_path)],
        ]
    else:
        commands = [
            ["open", str(pka_path)],
            ["open", "-a", PT_APP, str(pka_path)],
        ]

    last_error: Optional[str] = None
    for cmd in commands:
        result = run(cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            return
        last_error = (result.stderr or result.stdout or "").strip() or None

    if last_error:
        raise RuntimeError(f"failed to launch Packet Tracer for {pka_path.name}: {last_error}")
    raise RuntimeError(f"failed to launch Packet Tracer for {pka_path.name}")


def wait_for_activity_window(timeout: Optional[float] = None) -> int:
    effective_timeout = ACTIVITY_WINDOW_TIMEOUT if timeout is None else timeout
    deadline = time.time() + effective_timeout
    last_debug_dump = 0.0
    while time.time() < deadline:
        window_id = helper_window_id()
        if window_id is not None:
            if DEBUG_MODE:
                LOGGER.debug("activity_window_id=%s", window_id)
            return window_id
        if DEBUG_MODE and time.time() - last_debug_dump >= WINDOW_DEBUG_DUMP_INTERVAL:
            helper_window_debug()
            last_debug_dump = time.time()
        time.sleep(1.0)
    raise ActivityWindowNotFoundError(
        f"PT Activity window did not appear within {effective_timeout:.1f}s"
    )


def capture_window(window_id: int, screenshot_path: Path) -> None:
    if screenshot_path.exists():
        screenshot_path.unlink()
    run(["screencapture", "-x", "-l", str(window_id), str(screenshot_path)])
    if not screenshot_path.exists():
        raise ScreenshotCaptureError(f"screencapture did not create {screenshot_path.name}")
    if screenshot_path.stat().st_size == 0:
        raise ScreenshotCaptureError(f"{screenshot_path.name} is empty after capture")
    bounds = helper_window_bounds(window_id)
    if bounds is not None:
        _, _, _, window_height = bounds
        if window_height > 0:
            crop_result = run(
                [str(HELPER_BIN), "crop-activity", str(screenshot_path), str(window_height)],
                capture_output=True,
                text=True,
                check=False,
            )
            if crop_result.returncode != 0:
                raise ScreenshotCaptureError(
                    crop_result.stderr.strip()
                    or f"failed to crop screenshot {screenshot_path.name}"
                )
    if DEBUG_MODE:
        LOGGER.debug("captured_window=%s screenshot=%s", window_id, screenshot_path)


def capture_window_with_retry(
    window_id: int,
    screenshot_path: Path,
    attempts: int = 3,
    retry_delay: float = 0.75,
) -> int:
    current_window_id = window_id
    last_error: Optional[BaseException] = None

    for attempt in range(1, attempts + 1):
        try:
            capture_window(current_window_id, screenshot_path)
            return current_window_id
        except (subprocess.CalledProcessError, ScreenshotCaptureError) as exc:
            last_error = exc
            if DEBUG_MODE:
                LOGGER.debug(
                    "capture_window_failed attempt=%s window_id=%s reason=%s",
                    attempt,
                    current_window_id,
                    describe_exception(exc),
                )
            if attempt < attempts:
                time.sleep(retry_delay)
                refreshed = helper_window_id()
                if refreshed is not None:
                    current_window_id = refreshed
                continue

    if last_error is not None:
        raise last_error
    raise RuntimeError(f"failed to capture window {window_id}")


def normalize_ocr_line(line: str) -> str:
    return unicodedata.normalize("NFKC", re.sub(r"\s+", " ", line)).strip()


def has_pt_activity_indicators(lines: Sequence[str]) -> bool:
    for line in lines:
        lower = line.lower()
        if "pt activity" in lower or "for instructor use only" in lower:
            return True
        if re.search(r"\bcompletion\b\s*[:=]", line, re.IGNORECASE):
            return True
    return False


def detect_wrong_capture(lines: Sequence[str]) -> None:
    normalized = [normalize_ocr_line(line) for line in lines if line.strip()]
    if not normalized:
        return

    if has_pt_activity_indicators(normalized):
        return

    suspicious_patterns = (
        r"^(drwx|total\s+\d+|-r[-wx])",
        r"(^| )~/",
        r"(^| )/Users/",
        r"\bssh-rsa\b",
        r"\.csv\b",
        r"\.pka\b",
        r"\bpacket-tracer-completion\b",
        r"\bfind\b",
        r"\bpwd\b",
    )
    sample = normalized[:8]
    suspicious_hits = sum(
        1
        for line in sample
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in suspicious_patterns)
    )

    if suspicious_hits > 0:
        raise WrongWindowCaptureError(
            "recognized shell or filesystem text instead of PT Activity content"
        )


def parse_ocr_lines(lines: List[str]) -> Tuple[Optional[str], Optional[str]]:
    normalized = [normalize_ocr_line(line) for line in lines if line.strip()]

    completion = None
    for line in normalized:
        match = re.search(
            r"\bCompletion\b\s*[:=]?\s*([0-9]+(?:\.[0-9]+)?)\s*%?\*?",
            line,
            re.IGNORECASE,
        )
        if match:
            completion = match.group(1)
            break

    instructor = None
    stop_prefixes = (
        "Time Elapsed",
        "Completion:",
        "Top",
        "Dock",
        "Check Results",
        "Back",
        "Next",
        "1/",
        "Activity:",
        "Use the PDF",
    )

    for index, line in enumerate(normalized):
        if "for instructor use" not in line.lower():
            continue

        for follow in normalized[index + 1 :]:
            if not follow:
                continue

            label = re.sub(r"^[^A-Za-z0-9]+", "", follow)
            if label.startswith(stop_prefixes):
                continue

            instructor = follow
            break

        break

    return completion, instructor


def parse_activity_data(lines: List[str]) -> Tuple[str, str]:
    detect_wrong_capture(lines)
    completion, instructor = parse_ocr_lines(lines)
    normalized = [normalize_ocr_line(line) for line in lines if line.strip()]

    if not normalized:
        raise ScreenshotCaptureError("screenshot contains no OCR-readable text")

    if completion and instructor:
        return completion, instructor

    if completion and not instructor:
        raise InstructorMissingError(
            f"recognized completion value {completion}, but no instructor metadata below 'For instructor use only:'"
        )

    sample = " | ".join(normalized[:5])
    if sample:
        raise OCRParseError(f"recognized text sample: {sample}")

    raise ScreenshotCaptureError("screenshot contains no OCR-readable text")


def read_activity_data(
    screenshot_path: Path,
    timeout: Optional[float] = None,
) -> Tuple[str, str, List[str]]:
    effective_timeout = OCR_TIMEOUT if timeout is None else timeout
    deadline = time.time() + effective_timeout
    last_lines: List[str] = []
    last_error: Optional[PacketTracerDiagnosticError] = None

    while time.time() < deadline:
        try:
            lines = helper_ocr(screenshot_path)
            last_lines = lines
            completion, instructor = parse_activity_data(lines)
            if DEBUG_MODE:
                LOGGER.debug("parsed_completion=%s instructor=%s", completion, instructor)
            return completion, instructor, lines
        except PacketTracerDiagnosticError as exc:
            last_error = exc
            if DEBUG_MODE:
                LOGGER.debug("read_activity_data_retry screenshot=%s reason=%s", screenshot_path, exc.describe())
            if isinstance(exc, WrongWindowCaptureError):
                break
        time.sleep(1.0)

    if last_error is not None:
        raise type(last_error)(
            f"{last_error.message}; gave up after {effective_timeout:.1f}s"
        )

    raise OCRFailureError(
        "timed out parsing activity window OCR: " + " | ".join(last_lines[:10])
    )


def capture_and_read_activity_data(
    window_id: int,
    screenshot_path: Path,
    timeout: Optional[float] = None,
    settle_delay: float = 1.0,
) -> Tuple[str, str, List[str]]:
    effective_timeout = CAPTURE_OCR_TIMEOUT if timeout is None else timeout
    deadline = time.time() + effective_timeout
    last_lines: List[str] = []
    last_error: Optional[PacketTracerDiagnosticError] = None

    while time.time() < deadline:
        try:
            current_window_id = capture_window_with_retry(window_id, screenshot_path)
            time.sleep(settle_delay)
            lines = helper_ocr(screenshot_path)
            last_lines = lines
            completion, instructor = parse_activity_data(lines)
            if DEBUG_MODE:
                LOGGER.debug("parsed_completion=%s instructor=%s", completion, instructor)
            return completion, instructor, lines
        except PacketTracerDiagnosticError as exc:
            last_error = exc
            refreshed = helper_window_id()
            if refreshed is not None:
                if DEBUG_MODE and refreshed != window_id:
                    LOGGER.debug(
                        "refreshing_activity_window_id old=%s new=%s after=%s",
                        window_id,
                        refreshed,
                        exc.describe(),
                    )
                window_id = refreshed
            if DEBUG_MODE:
                LOGGER.debug(
                    "capture_read_retry screenshot=%s reason=%s",
                    screenshot_path,
                    exc.describe(),
                )
        time.sleep(0.75)

    if last_error is not None:
        raise type(last_error)(
            f"{last_error.message}; gave up after {effective_timeout:.1f}s"
        )

    raise OCRFailureError(
        "timed out parsing activity window OCR after fresh captures: "
        + " | ".join(last_lines[:10])
    )


def screenshot_name_for_folder(pka_files: List[Path], pka_path: Path) -> str:
    student_prefix = safe_stem(student_name_from_path(pka_path)) or "submission"
    if len(pka_files) == 1:
        return f"{student_prefix}_activity_window.png"
    return f"{student_prefix}_{safe_stem(pka_path.stem)}_activity_window.png"


def legacy_screenshot_name_for_folder(pka_files: List[Path], pka_path: Path) -> str:
    if len(pka_files) == 1:
        return "activity_window.png"
    return f"activity_window_{safe_stem(pka_path.stem)}.png"


def process_root(root: Path) -> bool:
    pka_files = sorted(root.rglob("*.pka"))
    if not pka_files:
        print(f"[skip] no .pka files in {root.name}")
        return False

    stale_root_screenshot = root / "activity_window.png"
    if stale_root_screenshot.exists() and stale_root_screenshot.is_file():
        stale_root_screenshot.unlink()

    csv_path = resolve_csv_path(root)
    existing_rows = read_existing_csv_rows(csv_path)
    output_rows: "OrderedDict[Tuple[str, str], List[str]]" = OrderedDict()
    root_incomplete = False
    print(f"[root] {root.name}: {len(pka_files)} submissions")
    if DEBUG_MODE:
        LOGGER.debug("process_root=%s submissions=%s csv=%s", root, len(pka_files), csv_path)
        LOGGER.debug("existing_rows=%s", list(existing_rows.keys()))

    for index, pka_path in enumerate(pka_files, start=1):
        student_name = student_name_from_path(pka_path)
        key = csv_key(student_name, pka_path.name)
        folder_files = [p for p in pka_files if p.parent == pka_path.parent]
        screenshot_path = expected_screenshot_path(pka_path, folder_files)
        existing_row = existing_rows.get(key)
        csv_present = existing_row is not None
        screenshot_exists = screenshot_path.exists()
        row_complete = row_is_complete(existing_row)

        print(f"[{index}/{len(pka_files)}] {student_name} -> {pka_path.name}")
        if DEBUG_MODE:
            LOGGER.debug(
                "submission_state student=%s file=%s row_complete=%s screenshot_exists=%s screenshot=%s",
                student_name,
                pka_path,
                row_complete,
                screenshot_exists,
                screenshot_path,
            )

        if row_complete and screenshot_exists:
            output_rows[key] = existing_row  # type: ignore[assignment]
            if DEBUG_MODE:
                LOGGER.debug("submission_skipped_complete student=%s file=%s", student_name, pka_path)
            continue

        if csv_present != screenshot_exists:
            root_incomplete = True

        completion = ""
        instructor = ""

        if row_complete and not screenshot_exists:
            if DEBUG_MODE:
                LOGGER.debug("submission_missing_screenshot student=%s file=%s", student_name, pka_path)
            try:
                open_pka_in_packet_tracer(pka_path)
                window_id = wait_for_activity_window()
                time.sleep(1.5)
                capture_window_with_retry(window_id, screenshot_path)
                completion, instructor = existing_row[2], existing_row[3]
            except Exception as exc:
                if DEBUG_MODE:
                    LOGGER.exception("screenshot_recovery_failed student=%s file=%s", student_name, pka_path)
                print(
                    f"    screenshot recovery failed for {pka_path.name}: {describe_exception(exc)}",
                    file=sys.stderr,
                )
                if existing_row is not None:
                    output_rows[key] = existing_row
                else:
                    output_rows[key] = [student_name, pka_path.name, "", ""]
                continue
            finally:
                if DEBUG_MODE:
                    LOGGER.debug("killing_packet_tracer after screenshot recovery %s", pka_path.name)
                kill_packet_tracer()
                wait_for_packet_tracer_exit()

            output_rows[key] = existing_row  # type: ignore[assignment]
            print("    screenshot recovered")
            continue

        if screenshot_exists and not row_complete:
            if DEBUG_MODE:
                LOGGER.debug("submission_missing_csv student=%s file=%s", student_name, pka_path)
            try:
                completion, instructor, _ = read_activity_data(screenshot_path)
                output_rows[key] = [student_name, pka_path.name, completion, instructor]
                print(f"    completion={completion} instructor={instructor}")
                continue
            except Exception as exc:
                if DEBUG_MODE:
                    LOGGER.exception("ocr_from_existing_screenshot_failed student=%s file=%s", student_name, pka_path)
                print(
                    f"    OCR failed for existing screenshot {pka_path.name}: {describe_exception(exc)}",
                    file=sys.stderr,
                )
                root_incomplete = True

        # Full recovery path: need to produce both screenshot and CSV row.
        last_error: Optional[Exception] = None
        success = False
        for attempt in range(1, SUBMISSION_RETRY_COUNT + 1):
            try:
                if DEBUG_MODE:
                    LOGGER.debug(
                        "submission_start student=%s file=%s attempt=%s screenshot=%s",
                        student_name,
                        pka_path,
                        attempt,
                        screenshot_path,
                    )
                open_pka_in_packet_tracer(pka_path, attempt=attempt)
                window_id = wait_for_activity_window()
                time.sleep(1.5)
                completion, instructor, _ = capture_and_read_activity_data(window_id, screenshot_path)
                output_rows[key] = [student_name, pka_path.name, completion, instructor]
                print(f"    completion={completion} instructor={instructor}")
                success = True
                break
            except Exception as exc:
                last_error = exc
                if DEBUG_MODE:
                    LOGGER.exception(
                        "submission_failed student=%s file=%s attempt=%s",
                        student_name,
                        pka_path,
                        attempt,
                    )
                print(
                    f"    attempt {attempt} failed for {pka_path.name}: {describe_exception(exc)}",
                    file=sys.stderr,
                )
            finally:
                if DEBUG_MODE:
                    LOGGER.debug("killing_packet_tracer after %s attempt=%s", pka_path.name, attempt)
                kill_packet_tracer()
                wait_for_packet_tracer_exit()

            if attempt < SUBMISSION_RETRY_COUNT:
                time.sleep(3.0)

        if not success:
            root_incomplete = True
            if existing_row is not None:
                output_rows[key] = existing_row
            else:
                output_rows[key] = [student_name, pka_path.name, "", ""]
            if DEBUG_MODE:
                LOGGER.debug(
                    "submission_exhausted student=%s file=%s attempts=%s last_error=%s",
                    student_name,
                    pka_path,
                    SUBMISSION_RETRY_COUNT,
                    last_error,
                )
            print(
                "    failed after "
                f"{SUBMISSION_RETRY_COUNT} attempts: "
                f"{describe_exception(last_error) if last_error else 'unknown failure'}",
                file=sys.stderr,
            )

    ordered_rows: List[List[str]] = [output_rows[csv_key(student_name_from_path(p), p.name)] for p in pka_files if csv_key(student_name_from_path(p), p.name) in output_rows]
    write_csv_rows(csv_path, ordered_rows)
    print(f"[done] wrote {csv_path}")
    if DEBUG_MODE:
        LOGGER.debug("wrote_csv=%s rows=%s incomplete=%s", csv_path, len(ordered_rows), root_incomplete)
    return root_incomplete


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Extract completion percentages and instructor metadata from "
            "Cisco Packet Tracer .pka submissions."
        )
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="write a detailed debug log for the run",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="explicit path for the debug log file; only used with --debug",
    )
    parser.add_argument(
        "--packet-tracer-app",
        type=Path,
        default=None,
        help="override the Cisco Packet Tracer app bundle path",
    )
    parser.add_argument(
        "--root-prefix",
        default=None,
        help="override the root folder prefix used for automatic discovery",
    )
    parser.add_argument(
        "--activity-window-timeout",
        type=positive_float,
        default=None,
        help="seconds to wait for the PT Activity window",
    )
    parser.add_argument(
        "--packet-tracer-exit-timeout",
        type=positive_float,
        default=None,
        help="seconds to wait for Packet Tracer to exit after force-kill",
    )
    parser.add_argument(
        "--ocr-timeout",
        type=positive_float,
        default=None,
        help="seconds to keep retrying OCR on an existing screenshot",
    )
    parser.add_argument(
        "--capture-ocr-timeout",
        type=positive_float,
        default=None,
        help="seconds to keep retrying fresh capture plus OCR for one submission",
    )
    parser.add_argument(
        "roots",
        nargs="*",
        type=Path,
        help=(
            "Submission root folders. If omitted, all matching folders below "
            "the script directory are processed."
        ),
    )
    return parser.parse_args(list(argv))


def main(argv: Optional[Sequence[str]] = None) -> int:
    if not HELPER_SRC.exists():
        print(f"missing helper source: {HELPER_SRC}", file=sys.stderr)
        return 1

    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        apply_runtime_config(args)
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 1

    log_file = setup_logging(args.debug, args.log_file)

    if DEBUG_MODE and log_file is not None:
        print(f"[debug] logging to {log_file}")
        LOGGER.debug("parsed_args=%s", args)

    try:
        compile_helper()

        roots = expand_requested_roots(args.roots) if args.roots else discover_roots(Path.cwd())
        roots = [root for root in roots if root.exists() and root.is_dir()]
        if not roots:
            print("no submission roots found", file=sys.stderr)
            if DEBUG_MODE:
                LOGGER.error("no submission roots found")
            return 1

        if DEBUG_MODE:
            LOGGER.debug("resolved_roots=%s", roots)

        any_incomplete = False
        for root in roots:
            any_incomplete = process_root(root) or any_incomplete

        if DEBUG_MODE:
            LOGGER.debug("=== packet-tracer debug session complete incomplete=%s ===", any_incomplete)
        return 2 if any_incomplete else 0
    except Exception as exc:
        if DEBUG_MODE:
            LOGGER.exception("unhandled failure in packet_tracer_batch")
        else:
            print(f"unhandled failure: {describe_exception(exc)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
