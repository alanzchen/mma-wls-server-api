# MaTeX Demo

This example demonstrates using [MaTeX](https://github.com/szhorvat/MaTeX) to render LaTeX expressions within the sandboxed WolframScript environment.

## Prerequisites

1. **Install MaTeX in Mathematica:**
   ```mathematica
   (* In Mathematica *)
   PacletInstall["MaTeX"]
   ```

2. **Install LaTeX toolchain:**
   ```bash
   # On macOS with Homebrew
   brew install texlive ghostscript
   ```

## Running the Demo

### Using the CLI tool:

```bash
# Execute the script
wls run examples/matex-demo.wls

# Or with directory sync to download generated PDFs
wls run examples/matex-demo.wls -d ./matex-output
```

### Using curl:

```bash
# Execute the script
curl -X POST \
  -F "file=@examples/matex-demo.wls" \
  -H "X-Runner-Password: your-password" \
  "http://localhost:8000/run?timeout=120"

# Download the generated PDFs
# Use the execution_id from the response
curl -O "http://localhost:8000/executions/<execution_id>/artifacts/equation1.pdf"
curl -O "http://localhost:8000/executions/<execution_id>/artifacts/equation2.pdf"
curl -O "http://localhost:8000/executions/<execution_id>/artifacts/matrix.pdf"
```

## What the Script Does

The script:
1. Configures MaTeX to use the sandbox-friendly paths for pdflatex and ghostscript
2. Sets the working directory to `~/.matex-tmp` for LaTeX temporary files
3. Renders three LaTeX expressions:
   - A simple equation: E = mc²
   - An integral expression
   - A matrix
4. Exports each rendered expression to a PDF file

## Customizing Paths

If your LaTeX/Ghostscript installation is in a different location, update the `ConfigureMaTeX` call in the script:

```mathematica
ConfigureMaTeX[
  "pdfLaTeX"         -> "/your/path/to/pdflatex",
  "Ghostscript"      -> "/your/path/to/gs",
  "WorkingDirectory" -> "/your/custom/temp/dir"
]
```

## Troubleshooting

If MaTeX fails to render:

1. **Check MaTeX installation:**
   ```mathematica
   PacletFind["MaTeX"]
   ```

2. **Verify tool paths:**
   ```bash
   which pdflatex
   which gs
   ```

3. **Check sandbox permissions:**
   The sandbox profile in `app/main.py` must include paths to your LaTeX installation. If you installed via MacTeX instead of Homebrew, you may need to update the sandbox profile.

4. **Enable debug output:**
   Add to your script:
   ```mathematica
   MaTeX`Developer`$Verbose = True
   ```
