# assets/demo.tape — records the README hero GIF.
#
# Record locally (neither vhs nor asciinema is bundled in CI):
#   1. Install vhs:          https://github.com/charmbracelet/vhs  (e.g. `brew install vhs`)
#   2. Install langdoctor:   pipx install langdoctor      (or from a clone: pip install -e .)
#   3. From the repo root:   vhs assets/demo.tape         ->  writes assets/demo.gif
#
# Asciinema alternative:
#   asciinema rec --command "langdoctor examples/vulnerable-agent" demo.cast
#   agg demo.cast assets/demo.gif        # https://github.com/asciinema/agg

Output assets/demo.gif
Require langdoctor

Set Shell bash
Set FontSize 15
Set Width 1120
Set Height 840
Set Padding 20
Set Theme "Catppuccin Mocha"

Hide
Type "clear"
Enter
Show

Sleep 600ms
Type "langdoctor examples/vulnerable-agent"
Sleep 1s
Enter
Sleep 6s
