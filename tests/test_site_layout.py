"""Guards for mobile layout bugs that silently broke swiping between tabs."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class MobileLayoutTests(unittest.TestCase):
    def test_auto_fill_grids_cannot_exceed_the_screen(self):
        # repeat(auto-fill, minmax(440px, 1fr)) is wider than a phone and made the Briefing panel scroll sideways,
        # which the swipe code (correctly) treats as "let this element scroll" - so swiping stopped working.
        css = (ROOT / "site" / "app.css").read_text(encoding="utf-8")
        bad = re.findall(r"repeat\(auto-(?:fill|fit),\s*minmax\(\d+px", css)
        self.assertEqual(bad, [], "use minmax(min(Npx,100%),1fr) so a column never exceeds the viewport")

    def test_panels_never_scroll_sideways(self):
        css = (ROOT / "site" / "app.css").read_text(encoding="utf-8")
        rule = re.search(r"\.panel\{[^}]*\}", css).group(0)
        self.assertIn("overflow-x:hidden", rule)


if __name__ == "__main__":
    unittest.main()
