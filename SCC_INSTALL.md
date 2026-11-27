# SCC installation guide

`scc` (Sloc, Cloc and Code) counts lines of code, comments, blanks, files and
languages in a repository. `Repo_analysis_tool.py` needs **exactly version
3.7.0** and stops before analysis if `scc` is missing or reports another version.

Every method below installs the official release from
[github.com/boyter/scc/releases/tag/v3.7.0](https://github.com/boyter/scc/releases/tag/v3.7.0).
`scc` is a system program, so install it outside the Python virtual environment.

- [Ubuntu / Linux](#ubuntu--linux)
- [Windows](#windows)
- [macOS](#macos)

## Ubuntu / Linux

1. Check the CPU architecture:

   ```bash
   uname -m
   ```

   `x86_64` uses `scc_Linux_x86_64.tar.gz`. `aarch64` uses `scc_Linux_arm64.tar.gz`.
   The commands below use `x86_64`; swap the file name if yours differs.

2. Install the download tools:

   ```bash
   sudo apt update
   sudo apt install -y wget tar
   ```

3. Download and extract scc 3.7.0:

   ```bash
   cd /tmp
   wget https://github.com/boyter/scc/releases/download/v3.7.0/scc_Linux_x86_64.tar.gz
   tar -xzf scc_Linux_x86_64.tar.gz
   ./scc --version
   ```

   Continue only if it prints `3.7.0`.

4. Install it for all users and check the result:

   ```bash
   sudo install -m 755 scc /usr/local/bin/scc
   hash -r
   command -v scc
   scc --version
   ```

   The path should be `/usr/local/bin/scc` and the version `3.7.0`.

If an older Snap package of scc comes first on the PATH, remove it with
`sudo snap remove scc`, run `hash -r`, and check `command -v scc` again. Only do
this if `snap list scc` shows it installed.

## Windows

Use PowerShell **as Administrator** (search for PowerShell, right-click, then
**Run as administrator**). Pick one of the two options.

### Option 1: Chocolatey

If `choco --version` fails, install Chocolatey first by following
[chocolatey.org/install](https://chocolatey.org/install). Then run:

```powershell
choco install scc --version=3.7.0 -y
scc --version
```

### Option 2: Manual install

1. Download and extract the 64-bit build:

   ```powershell
   cd $env:TEMP
   Invoke-WebRequest -Uri "https://github.com/boyter/scc/releases/download/v3.7.0/scc_Windows_x86_64.zip" -OutFile "scc.zip"
   Remove-Item "$env:TEMP\scc" -Recurse -Force -ErrorAction SilentlyContinue
   Expand-Archive -Path "scc.zip" -DestinationPath "scc" -Force
   Get-ChildItem "$env:TEMP\scc"
   ```

   The folder should contain `scc.exe`.

2. Copy it to `C:\Program Files\scc`:

   ```powershell
   New-Item -ItemType Directory -Path "C:\Program Files\scc" -Force
   Copy-Item "$env:TEMP\scc\scc.exe" "C:\Program Files\scc\scc.exe" -Force
   ```

3. Add that folder to the system PATH:

   ```powershell
   $sccPath = "C:\Program Files\scc"
   $oldPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
   if ($sccPath -notin ($oldPath -split ";")) {
       [Environment]::SetEnvironmentVariable("Path", "$oldPath;$sccPath", "Machine")
   }
   ```

4. Close PowerShell, open a new window, and check:

   ```powershell
   scc --version
   Get-Command scc -All
   ```

   The version must be `3.7.0`. If `Get-Command` lists more than one `scc`, the
   first one wins; remove or reorder the others.

## macOS

1. Check the CPU architecture:

   ```bash
   uname -m
   ```

   `arm64` is Apple Silicon and uses `scc_Darwin_arm64.tar.gz`. `x86_64` is
   Intel and uses `scc_Darwin_x86_64.tar.gz`.

2. Download and extract scc 3.7.0 (Apple Silicon shown; use the Intel file name
   on an Intel Mac):

   ```bash
   cd /tmp
   curl -fL -o scc_Darwin_arm64.tar.gz "https://github.com/boyter/scc/releases/download/v3.7.0/scc_Darwin_arm64.tar.gz"
   tar -xzf scc_Darwin_arm64.tar.gz
   chmod +x scc
   ./scc --version
   ```

   Continue only if it prints `3.7.0`.

3. Install it and check the result:

   ```bash
   sudo mkdir -p /usr/local/bin
   sudo install -m 755 scc /usr/local/bin/scc
   hash -r
   command -v scc
   scc --version
   ```

   The path should be `/usr/local/bin/scc` and the version `3.7.0`.

Don't use `brew install scc`: Homebrew ships a newer scc (4.1.0 in November
2026), and the tool rejects it. If `type -a scc` shows a Homebrew copy ahead of
`/usr/local/bin/scc`, run `brew uninstall scc` or put `/usr/local/bin` first
with `export PATH="/usr/local/bin:$PATH"`.

## Optional: verify the download

Each release ships a `checksums.txt`. To check a Linux or macOS download before
installing it, run this in the folder that holds the archive:

```bash
curl -fsSL https://github.com/boyter/scc/releases/download/v3.7.0/checksums.txt | grep scc_Darwin_arm64.tar.gz | shasum -a 256 -c
```

Replace the file name with the one you downloaded. It should print `OK`.
