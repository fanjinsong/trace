"""Render Lua frames in green without modifying the FlameGraph submodule."""

from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory


LUA_COLOR = "rgb(96,184,110)"


def render_flamegraph(folded, svg, *, pid, perl, script):
    folded, svg, script = Path(folded).resolve(), Path(svg).resolve(), Path(script).resolve()
    lua_frames = set()
    for line in folded.read_text(encoding="utf-8").splitlines():
        if line.strip():
            stack, count = line.rsplit(" ", 1)
            lua_frames.update(frame for frame in stack.split(";") if frame.startswith("lua:"))

    # --cp reads and writes palette.map in its working directory. Isolate it
    # so concurrent captures cannot change each other's frame colors.
    with TemporaryDirectory(prefix="mixed-flamegraph-") as directory:
        palette = Path(directory) / "palette.map"
        palette.write_text("".join("%s->%s\n" % (frame, LUA_COLOR)
                                   for frame in sorted(lua_frames)), encoding="utf-8")
        with svg.open("w", encoding="utf-8") as stream:
            subprocess.run([
                perl, str(script), "--title", "Mixed CPU Profile (PID %d)" % pid,
                "--subtitle", "Lua: green | Native: warm colors",
                "--countname", "samples", "--bgcolors", "#f8fafc", "--cp", "--hash",
                str(folded),
            ], cwd=directory, stdout=stream, check=True)
