# Packet Tracer Submission Evaluator

This tool evaluates Cisco Packet Tracer `.pka` submissions automatically.

For each submission, it:

1. opens the `.pka` file in Cisco Packet Tracer
2. captures a screenshot of the `PT Activity` window
3. reads the `Completion` percentage
4. reads the line directly below `For instructor use only:` when that section exists
5. writes the result into a CSV file in the submission root folder

## Important Notes

- This tool is built for macOS and the macOS GUI version of Cisco Packet Tracer.
- Packet Tracer is force-terminated after each submission because it may hang when closing normally.
- The screenshots must include the lower `Completion` area. The tool now crops the capture to the relevant PT Activity area to reduce OCR noise.
- You can pass one or more submission root folders to the launcher.
- If a run was interrupted before, the tool can resume and fill in missing CSV rows or missing screenshots.
- If you stop the tool with `Ctrl-C`, it exits cleanly, attempts Packet Tracer cleanup, and returns exit code `130`.

## Requirements

- macOS
- Cisco Packet Tracer 9.0.0
- Python 3
- `swiftc` from Apple Command Line Tools or Xcode

`python3` is used to run the main batch logic, traverse submission folders, control the workflow, write CSV files, and manage retries and resume behavior.

`swiftc` is used to compile the small helper program in `packet_tracer_helpers.swift`. That helper detects the correct `PT Activity` window and performs OCR on screenshots.

If `swiftc` is missing:

```bash
xcode-select --install
```

## Usage

If the files are in the project folder:

```bash
cd "/path/to/Packet Tracer Evaluation"
./packet-tracer-completion "/path/to/submission-root"
```

If you do not pass a folder, the current folder is processed:

```bash
cd "/path/to/submission-root"
packet-tracer-completion
```

If you later copy the tool into `~/bin`, the usage stays the same:

```bash
packet-tracer-completion "/path/to/submission-root"
```

You can override the Packet Tracer app path, root discovery prefix, and the main timeouts on the command line:

```bash
packet-tracer-completion \
  --packet-tracer-app "/Applications/Cisco Packet Tracer 9.0.0/Cisco Packet Tracer 9.0.app" \
  --root-prefix "240304-Abgabe Packet Tracer HUE ITSB-B" \
  --activity-window-timeout 300 \
  --packet-tracer-exit-timeout 20 \
  --ocr-timeout 20 \
  --capture-ocr-timeout 30 \
  "/path/to/submission-root"
```

The same settings can also be provided by environment variables:

- `PACKET_TRACER_APP`
- `PACKET_TRACER_ROOT_PREFIX`
- `PACKET_TRACER_ACTIVITY_WINDOW_TIMEOUT`
- `PACKET_TRACER_EXIT_TIMEOUT`
- `PACKET_TRACER_OCR_TIMEOUT`
- `PACKET_TRACER_CAPTURE_OCR_TIMEOUT`

Priority is:

1. command-line option
2. environment variable
3. built-in default

## Debug Mode

For troubleshooting, run:

```bash
packet-tracer-completion --debug "/path/to/submission-root"
```

You can also choose the log file path explicitly:

```bash
packet-tracer-completion --debug --log-file "/path/to/debug.log" "/path/to/submission-root"
```

Debug logging includes:

- startup arguments and working directory
- resolved runtime configuration
- executed shell commands and helper calls
- detected Packet Tracer windows
- OCR output lines
- focused Packet Tracer process cleanup details
- failures and unexpected tracebacks

The tool now also classifies common failures more clearly, for example:

- `Activity window not found`
- `Screenshot empty or unusable`
- `OCR failed`
- `Instructor section present, but no instructor metadata could be parsed`
- `OCR returned text, but the parser found no usable match`
- `Wrong window capture suspected`

## Resume Behavior

If partial output already exists for a student, the tool does not rebuild everything from scratch.

Rules:

- If both the CSV row and the screenshot already exist, the entry is skipped.
- If only one part exists, only the missing part is regenerated.
- If at least one student had only partial output, the run is considered incomplete.
- In that case, the tool exits with code `2`.

This is useful after interrupted runs.

## Output

Inside each submission root folder, the tool creates:

- a CSV file, usually `completion.csv` unless you renamed the existing root CSV and want the tool to continue writing into that file
- one screenshot per submission, named like `Student_Name_activity_window.png`

If a submission folder still contains an older screenshot name from a previous run, the tool reuses it by renaming it to the current format during resume.

The CSV format is:

```text
Name des Studenten;filename;completition;instructor_use_only;duplicate_instructor_use_only
```

If the same `instructor_use_only` value appears more than once within the same CSV, the column `duplicate_instructor_use_only` is set to `yes` for all affected rows.

Some Packet Tracer activities do not include a `For instructor use only:` section at all. In that case, the tool still records the `Completion` value and leaves `instructor_use_only` empty.

CLI progress output is written as one line per submission, for example:

```text
[5/50] Birgit Hurer -> Hurer_10.3.5 Packet Tracer - Troubleshoot Default Gateway Issues.pka completion=100 instructor=
```

If the tool finds a subdirectory that contains files but no `.pka`, it prints a warning with the directory and filenames, for example:

```text
[warn] CNE1test/some-folder: no .pka files found; files=notes.txt, screenshot.png
```

## Files

### `packet-tracer-completion`

End-user shell launcher.

It:

- locates the actual script files
- forwards the target folder arguments
- can be executed directly from `~/bin`

### `packet_tracer_completion.py`

Entry point for the Python tool.

It:

- parses command-line arguments
- starts the evaluation
- processes either explicit folders or matching submission roots automatically

### `packet_tracer_batch.py`

Main evaluation logic.

It:

- finds `.pka` files
- opens each submission in Packet Tracer
- waits for the `PT Activity` window
- creates screenshots
- extracts completion and instructor metadata by OCR
- writes the CSV file
- force-kills Packet Tracer after each submission

### `packet_tracer_helpers.swift`

Small helper program compiled at runtime with `swiftc`.

It:

- finds the correct `PT Activity` window
- returns exact window bounds for screenshots
- performs OCR on the captured image

The compiled helper binary is created at runtime in `/tmp/packet_tracer_helpers`.

## Installation Into `~/bin`

If you want to use the tool independently from the project folder, copy these files into `~/bin`:

- `packet-tracer-completion`
- `packet_tracer_completion.py`
- `packet_tracer_batch.py`
- `packet_tracer_helpers.swift`

Then make the launcher executable:

```bash
chmod +x ~/bin/packet-tracer-completion
```

If `~/bin` is not yet in your `PATH`, add it to your shell configuration.
