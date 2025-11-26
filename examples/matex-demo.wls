#!/usr/bin/env wolframscript
(* MaTeX Demo Script

   This script demonstrates using MaTeX to render LaTeX expressions
   within the sandboxed environment.

   Prerequisites:
   - MaTeX package installed in Mathematica
   - pdflatex and ghostscript installed (brew install texlive ghostscript)
*)

(* Load MaTeX package *)
<< MaTeX`

(* Configure MaTeX to use the sandbox-friendly working directory *)
ConfigureMaTeX[
  "pdfLaTeX"         -> "/opt/homebrew/bin/pdflatex",
  "Ghostscript"      -> "/opt/homebrew/bin/gs",
  "WorkingDirectory" -> FileNameJoin[{$HomeDirectory, ".matex-tmp"}]
]

(* Test if MaTeX is configured correctly *)
Print["MaTeX Configuration:"];
Print["  pdfLaTeX: ", MaTeX`Developer`$pdfLaTeX];
Print["  Ghostscript: ", MaTeX`Developer`$Ghostscript];
Print["  Working Directory: ", MaTeX`Developer`$WorkingDirectory];
Print[""];

(* Create a simple LaTeX expression *)
Print["Rendering simple expression: E = mc^2"];
expr1 = MaTeX["E = mc^2", Magnification -> 2];
Export["equation1.pdf", expr1];
Print["Exported to equation1.pdf"];
Print[""];

(* Create a more complex expression *)
Print["Rendering integral expression"];
expr2 = MaTeX["\\int_{0}^{\\infty} e^{-x^2} dx = \\frac{\\sqrt{\\pi}}{2}", Magnification -> 2];
Export["equation2.pdf", expr2];
Print["Exported to equation2.pdf"];
Print[""];

(* Create a matrix *)
Print["Rendering matrix"];
expr3 = MaTeX["\\begin{pmatrix} a & b \\\\ c & d \\end{pmatrix}", Magnification -> 2];
Export["matrix.pdf", expr3];
Print["Exported to matrix.pdf"];
Print[""];

Print["MaTeX demo completed successfully!"];
Print["Check the exported PDF files for rendered LaTeX expressions."];
