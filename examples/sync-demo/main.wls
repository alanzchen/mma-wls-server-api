(* Example WolframScript demonstrating folder sync *)

Print["=== Folder Sync Demo ==="];
Print["Working directory: ", Directory[]];

(* List files in current directory *)
Print["\nFiles in execution directory:"];
files = FileNames["*", Directory[], Infinity];
Do[Print["  - ", file], {file, files}];

(* Read data file if it exists *)
dataFile = FileNameJoin[{Directory[], "data", "input.txt"}];
If[FileExistsQ[dataFile],
  Print["\nReading data file:"];
  Print[Import[dataFile, "Text"]],
  Print["\nNo data file found at: ", dataFile]
];

(* Create an output file *)
outputDir = FileNameJoin[{Directory[], "output"}];
If[!DirectoryQ[outputDir], CreateDirectory[outputDir]];
outputFile = FileNameJoin[{outputDir, "result.txt"}];
Export[outputFile, "Execution completed at " <> DateString[], "Text"];
Print["\nOutput written to: output/result.txt"];

Print["\n=== Demo Complete ==="];
