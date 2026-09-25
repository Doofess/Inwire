# 0046 — Export is the whole capture, streamed

**Status:** accepted. Builds on [0031](0031-a-filter-answers-over-the-whole-capture.md)
for the filtered scope and on [0006](0006-pcapng-writer-scope.md) for pcapng's block
set; supersedes neither.

## Context

**Every export was the RAM window.** Since 0025 the capture lives on disk and the
buffer is only its newest part, but the Export panel wrote `packets` and nothing
else. A capture that had outgrown the buffer exported its newest few hundred
thousand frames, and the file did not say it was short.

**Saving held the whole file.** `saveGeneratedBlob` called `blob.arrayBuffer()`
and sent the result to main in one IPC message, which then called `writeFile`. So
a file larger than the renderer's heap could never be exported, even with the
frames available.

The rest was about what a file said:

- **The PDF was a packet list** titled "Net View Analysis Report". PDF import
  existed only to read that table back.
- **CSV, Excel and JSON carried the list's columns** and none of the dissection.
  JSON carried a `layers` tree, which is empty on every frame the pipeline posts
  (0007).
- **Metadata was thin, and in places wrong.** A null `droppedKernel` was written
  as 0 and `droppedPipe` was ignored. An anonymised export leaked addresses
  through expert messages, because `pcapParser.ts` writes addresses into that
  prose.
- **Excel had one blue header**, and its times were strings.
- **A row read off disk had no `linkType`.** The chunk layout never stored it. A
  disk-backed export of a loopback capture would have reached the writers labelled
  Ethernet, and the anonymiser rewrites bytes at link-layer offsets.

## Decision

### A save that streams, and the chosen name appears only on commit

Three new channels, `inwire:save-stream-open`, `-write` and `-close`. The handlers
are in `electron/saveStream.ts`. The rules are in `electron/saveSession.ts`, which
does not import `electron`: the same split as `saveTarget.ts` beside `saveFile.ts`.

- **The dialog opens first.** An export whose dialog is cancelled has read nothing.
- **Bytes go to `<target>.<random>.partial`**, created with `wx`. The partial is
  renamed to the target on commit and deleted on abort. The name is random rather
  than `<target>.partial` because the app must never open or delete a file with a
  predictable name that it did not create.
- **An existing target is probed with `r+` before anything is spent.** That fails
  fast for a read-only file, or one another program holds without write sharing.
- **A failed rename keeps the partial** and names it in the error. Wireshark
  holding the target open is enough to make `rename` answer `EPERM` (measured on
  Windows 11), and throwing away minutes of export over a lock that takes a second
  to release is worse.
- **A token belongs to the webContents that opened it.** That window's partials
  are deleted if it is destroyed, crashes or navigates. `will-quit` deletes every
  partial with synchronous calls, because nothing awaited at quit is guaranteed to
  run.
- **Limits:** `MAX_OPEN_SAVES` is 4, and one write is at most 64 MB
  (`MAX_WRITE_BYTES`).

In the renderer, `src/lib/saveSink.ts` defines a `ByteSink` (`write`, `close`,
`abort`). The bridge sink gathers writes into 2 MB IPC messages, `zipSink`
compresses as it goes through fflate's `Zip`/`ZipDeflate`, and `MemorySink` is
the same contract for scripts. The whole-file `inwire:save-file` channel stays,
for Follow Stream's save.

### The frames: disk below the window, the window from memory

`services/export/exportFrames.ts` is an async generator of pages.

**The disk half** reads capture ordinals `[0, below)` off the store and clips at
`below`. The chunk holding `below` also holds window frames, and without the clip
the window's oldest frames would be written twice.

**`below` is asked of the store** (`windowOrdinal`), for the window this export
was given. It is never taken from the list's `useWindowOrdinal`, because that is
an async answer about an earlier window. A trim in between would leave it too
small, and the frames between the two ordinals would be in neither half while
`done === total` said the file was whole.

If the store cannot place the window's first frame yet, it is asked again ten
times, 200 ms apart. After that the export is refused with the reason. It is
refused rather than guessed, because a file silently missing those frames is
exactly the failure this ADR exists to end.

**The window half is read from memory** even though disk has it. That is what
the list shows, Info patches included, and its newest frames are not sealed on
disk yet.

**Every yielded frame is a shallow copy.** Setting `rawBytes` on the buffer's own
objects would quietly undo `evictOldBytes` for the rest of the session. Bytes are
hydrated per page through `packetsBytes`, and only for writers that write them:
the PDF reads none, and CSV/JSON read them only when *Include raw packet bytes*
is on.

**A chunk that cannot be read is skipped, not the end of the export.** It takes
at most two bounded reads. Its frames are counted as `unreadable` and printed in
the metadata. A store that answers nothing counts everything left and stops,
because a loop that kept asking would be a hang with a progress bar.

### The filtered scope is the list's own scan

The export runs no scan of its own. The store runs one scan at a time, so a
second would cancel the list's. Disk rows come from the list's `MatchSet` and
window rows from `FilterEngine.filterPackets`, the same split
`lib/captureRowSpace.ts` makes. The file therefore holds exactly the frames the
list shows.

Between matches the reader **jumps**, to `ordinalAt(rank(at))`, so a chunk with
no match is never decoded. The panel offers the filtered choice only when the
scan has covered every frame on disk. While scanning it shows `scanning n%`. When
frames arrived after the scan, or the scan failed, the choice is disabled with
the reason and a Rescan button.

### Chunk version 2 records each frame's link type

`CHUNK_VERSION` is 2. Each row carries a `u16` `linkType`, with `0xffff` meaning
absent. Absent means Ethernet, the same convention the dissector uses.

**Version 1 still decodes.** A capture on disk outlives the build that wrote it.
`chunkStoresLinkType` and `RowBlock.linkTypesStored` tell a reader which meaning
an absence has. Only a v1 row falls back to `linkTypeTable`, keyed by adapter
label.

The table cannot be the primary source because **a label is not an adapter**.
Every frame of an import carries the same label, so a multi-interface pcapng has
one label and two link types.

### A survey before the first byte

CSV and Excel write every dissected field as a column, so the column set must be
fixed before the first row. A whole-capture export never holds the capture, so it
cannot read that set off an array. `runExport` therefore makes one pass over the
rows first, without bytes.

That pass collects four things:

- the union of field keys (`FieldSurvey`);
- the frame count and the first and last timestamps, which the metadata needs
  before its first line;
- pcapng's name table;
- the adapters, in order of first appearance.

pcap prints no metadata and skips the survey. The PDF's analysis is its own pass.

**Columns are wide, one per field.** They are ordered by `LAYERS`, then by
registry position. Each header is the exact Wireshark abbreviation, which a
reader can paste into the filter bar.

The importer ignores dotted headers when it matches its own columns, so
`frame.len` cannot take over Length. It also skips a leading `# key: value`
preamble while still accepting a bare `#` as the No. header.

### One writer per format

The writers are in `services/export/writers/{pcap,pcapng,csv,json,xlsx}.ts`. Each
has `write(page, rules?)`, which returns `Uint8Array[]`, and `finish()`. They stay
synchronous and never touch the sink, so one writer serves both the streamed save
and the one-shot wrappers the scripts use. The wrappers are `export/oneShot.ts`,
`pcapngWriter.generatePcapNg` and `tabularWriters.buildCsvText`. They left
`pcapParser.ts`, because that file is in the entry chunk and everything it names
comes with it.

**The two capture formats go through `orderByTime.ts`.** It holds a page of
lookahead, so a file stays in time order without the capture ever being held
whole.

**pcapng is written front to back.** The survey knew the counts, so the SHB goes
first and complete. Then come the DSB when there are secrets, an IDB immediately
before each adapter's first frame (numbered in order of first appearance), and
the EPBs. The NRB and the ISB come at `finish`.

Paging is invisible in the output: pages of any size give the same bytes as the
one-shot writer.

The ISB is still written only when the file holds exactly one adapter:

- `isb_ifdrop` is the kernel count;
- `isb_osdrop` is agent + pipe, written only when both are known;
- a null count is never written as 0.

**JSON is version 2:**
`{"format":"inwire-export","formatVersion":2,"meta":…,"packets":[…]}`, with one
frame per line. It drops `layers` and gains `fields` (unless anonymised),
`protocols`, `analysisFlags`, direction, stream and colour rule. The importer
accepts it through its `{packets}` path.

### Metadata in every format, and none in classic pcap

There is one record, `CaptureMeta`, and one formatter, `metaEntries`
(`export/captureMeta.ts`). Numbers are `en-US` and times are UTC ISO-8601 to the
microsecond, never in the viewer's locale. **A count nobody reported prints as
"not available"**, because a zero claims the capture is complete, and nobody
measured that.

Where each format prints it:

- **pcapng:** in the SHB comment, with `shb_userappl` set to `Inwire <version>`
  (`__INWIRE_VERSION__`, a Vite `define` of `package.json`'s version) and
  `shb_os` set by the caller. `services/` does not read `window`.
- **CSV:** in quoted `# key: value` lines above the header.
- **JSON:** in `meta`, where a null stays null.
- **Excel:** on the Capture sheet.
- **PDF:** on the cover.

**Classic pcap has nowhere to put it**, and it writes none. The panel's pcap row
says what it loses.

### One anonymiser per job

Prefix-preserving anonymisation is keyed: two anonymisers map one address to two
pseudonyms. So `runExport` constructs one `Anonymiser` before the first page and
uses it for every page, the metadata and the report. A host keeps one pseudonym
across the disk/window boundary, and between a pcapng and a report written by the
same job. `scripts/session/side-bar.ts` holds the file to exactly one
`new Anonymiser(`, outside the page loop.

Everything that needs the real frame sees it first:

- the colour rule (`RuleMatcher`, with an engine of its own on a copy, so no
  `colorSlot` in the list is touched);
- the survey;
- the name table;
- the PDF's analysis.

What those produce is redacted with the same anonymiser (`report/redact.ts`),
never recomputed from anonymised frames. Expert messages go through the new
`Anonymiser.text`.

An anonymised file writes no field columns, because every address, port and name
in the field bag is what anonymising removes. It carries no NRB and no secrets:
the pcapng writer throws if handed either.

### Excel is buffered, and so it is budgeted

The browser build of exceljs has only `Workbook`, with no `stream.xlsx`. Excel is
therefore the one format that holds its whole output until `writeBuffer`. It is
refused rather than attempted past what fits:

- 1,048,575 data rows, and `XLSX_BUDGET.cells` cells, which is
  `XLSX_HEAP_BUDGET` (1.25 GiB) ÷ `XLSX_BYTES_PER_CELL` (720), or 1,864,135 cells;
- over budget, the field columns are dropped first, and the Capture sheet says so;
- still over, the export is refused with a message that names CSV.

**The polish:**

- The Packets sheet stays first, with its header on row 1, because the importer
  depends on that.
- Standard cells are painted in their colour rule's **Day** colours whatever the
  app's theme, because a spreadsheet is a white document. Each (rule, number
  format) pair has one style object, assigned to every cell that uses it.
- Panes are frozen at `xSplit:1, ySplit:1`, with an autofilter.
- Values are real numbers, and Arrival (UTC) is a date.
- **Epoch (ms) is text.** Excel keeps 15 significant digits, and an epoch to the
  microsecond has 16.
- The Protocols sheet is an indented hierarchy. Alerts became **Findings**,
  grouped as the Expert pane groups them. **Capture** holds the metadata and a
  legend of the colour rules the capture matched.

### The PDF is an analysis of the capture

`report/analysis.ts` is a fold, `CaptureAnalyzer`, built from the folds the
Statistics pane already uses, so the two cannot disagree. It adds the signals no
pane shows. `report/findings.ts` turns those numbers into deterministic sentences.

`components/export/pdfReport.ts` draws the report with jsPDF, using vector
primitives from `pdfCharts.ts` and no DOM. The sections are:

- a cover with the mark and the metadata;
- a summary, then findings;
- traffic over time and the protocol hierarchy;
- packet sizes, top endpoints and top conversations;
- expert findings, hosts, processes and methods.

It has **no packet list**. The frames belong in pcapng, CSV or JSON.

Text is WinAnsi-only. Anything else becomes `?`, and the Methods note says when
that happened. The report reads no bytes.

**PDF import is removed, and `pdfjs-dist` with it** (22f9594): with no packet
table there is nothing to read back.

### The job outlives the panel, and none of it is in the entry chunk

`export/exportJob.ts` is a module store, the shape of `packetCounts.ts`, so
progress and Cancel survive the side bar switching panels. It runs one job at a
time and refuses a second rather than queueing it. `TransferPanel` reaches
`runExport` only through `await import`. The writers, the anonymiser, exceljs and
jsPDF are all fetched when a format is pressed.

## What it measured

**Bundle** (`scripts/perf/bundle-size.ts`, bytes):

| | eager JS | total |
|---|---|---|
| before this work | 2,454,889 | 9,637,443 |
| after PDF import and `pdfjs-dist` were removed (22f9594) | 2,454,338 | 7,495,595 |
| after the whole overhaul, this build | 2,449,928 | 7,573,766 |

Removing `pdfjs-dist`, and aliasing jsPDF's unused `html2canvas`, `dompurify` and
`canvg` to a stub that throws, took **2.14 MB** off the total.

The overhaul then added **78 kB** of lazily fetched code:

- `runExport` is 40.7 kB;
- the analysis is 9.2 kB;
- the `pdfReport` chunk, which carries jsPDF and autotable, is 448 kB;
- exceljs is unchanged at 940 kB.

The eager chunk fell only **4.4 kB net**. The writers, the anonymiser and
pcapng's block builder left it, and the panel's new scope and progress UI and the
job store joined it. So the lazy import is worth having for what it keeps out,
and it is not a launch-time win.

**Excel** (`node --expose-gc --import tsx scripts/perf/xlsx-cost.ts`, both
fixtures, bytes per Packets-sheet cell):

| workbook | cells | retained | peak | µs/cell |
|---|---|---|---|---|
| inwire, standard columns | 218,586 | 242 | 1,193 | 3.80 |
| inwire + fields | 561,729 | 217 | 1,160 | 2.20 |
| bulk + fields | 663,882 | 215 | 1,025 | 2.06 |
| bulk + fields + raw bytes | 678,664 | 665 | 1,532 | 4.26 |
| bulk ×4 + fields | 2,655,528 | 215 | **557** | 2.04 |

**A cell retains about 215 B whatever the capture.** The peak, while `writeBuffer`
holds the model and its output together, settles towards ~550 B as the workbook
grows. The small workbooks' higher peak is fixed cost spread over few cells.

A sampled peak understates a constrained heap, because V8 collects later than it
could. The ×4 workbook **died at a 1,600 MB heap limit and finished at 2,000 MB,
peaking at 704 B a cell**. So the figure is 720, and 1.25 GiB of the renderer's
4,192 MB heap is ~1.86 million cells. That is about 110,000 frames of standard
columns, or ~45,000 with every field at the fixtures' 27 fields a frame.

The script's default run also writes the capture 12 times over, about 8 million
cells, and **that run takes the measuring process past V8's 4 GB heap and
aborts**. The instrument itself makes the budget's argument. Pass
`XLSX_COST_REPEATS=4` to get the table.

## What was rejected

- **An export that runs its own scan.** The store runs one scan at a time. A
  second scan would cancel the list's, and while running it would give an answer
  the list does not show.
- **`row.fill`.** exceljs writes it as a row style, which Excel applies across
  all 16,384 columns and so paints the empty width right of the table. Fills go
  on cells.
- **Long-format CSV**, with one row per (frame, field). It would stop a row being
  a frame, so the importer could not read the file back and a spreadsheet user
  would have to pivot before filtering.
- **`printToPDF`.** A page printed by Chromium cannot be run under plain `tsx`, so
  no assertion script could read the report. jsPDF can.
- **A fixed `<target>.partial` name.** A file of that name the app did not create
  would be truncated on open and deleted on abort.
- **Building the pcapng SHB at `finish` and moving it to the front.** The survey
  already knows every number the header prints, so it is written first, and a
  streamed file never has to go back.

## Consequences

- **Every export except pcap and the PDF reads the capture twice.** The survey is
  a second read of every row, without bytes. Its cost on a multi-million-frame
  capture has **not** been measured.
- **An export of a live capture is a snapshot** as of the press. A filtered
  export covers only what the scan covered, which is also what the list shows.
- **A CSV now opens with `# key: value` lines.** The importer skips them. A third
  party reading row 1 as the header will not, and needs to be told to skip lines
  that start with `#`.
- **JSON v1 readers break.** The importer reads both versions, since a bare
  array is still accepted.
- **`total` in `test/perf/ceilings.json` has to rise** to exactly this build, by
  78,171 B. That is the one kind of raise `bundle-size.ts` permits (0041), and it
  is made on purpose in its own commit. `eagerJs` can be lowered by the 4.4 kB it
  fell.
- **Excel refuses a large export** and says to use CSV. Everything past about
  110,000 frames of standard columns goes to CSV.
- **The tests are the real captures** (ADR 0004), and each skips cleanly without
  them:
  - `scripts/export/whole-capture.ts` checks the iterator over a real
    `CaptureHost`, every append crossing `v8.serialize`;
  - `scripts/export/run-export.ts` checks every format end to end, read back by
    something other than its writer (tshark for pcapng when present);
  - `scripts/export/save-stream.ts` checks the partial files against a real
    directory;
  - `scripts/export/xlsx-style.ts` checks the workbook's styling;
  - `scripts/report/{folds,analysis,findings}.ts` check the report;
  - `pcap.ts`, `pcapng.ts`, `tabular.ts`, `anonymise.ts` and `pdf-report.ts`
    check the rest.

  What no script can check, such as Wireshark's Capture File Properties, Excel
  opening the file without repair, and the PDF in print, is in
  `docs/verification.md`.
