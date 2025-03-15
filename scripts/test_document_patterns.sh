#!/bin/bash
#
# test_document_patterns.sh
#
# This software is dual-licensed under:
# - GNU Affero General Public License v3.0 (AGPLv3) - for those willing to comply with AGPLv3 terms
# - Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms
#
# If you do not want to be bound by the AGPLv3 terms (such as releasing source code
# for modifications or network usage), you must acquire a proprietary license.
#
# See the LICENSE file for details.


# Document and clarify the behavior of different MuonFP pattern formats
# This script is informational only - it doesn't modify anything

echo "=== MuonFP Pattern Format Documentation ==="
echo "This script demonstrates how different patterns are interpreted"
echo ""

echo "== Pattern: \"1024:::\" =="
echo "This pattern means:"
echo "  - Window size MUST be 1024"
echo "  - NO options are allowed at all"
echo "  - NO MSS value (because no MSS option is allowed)"
echo "  - NO window scale value (because no window scale option is allowed)"
echo "  - This matches the Nmap default SYN scan pattern"
echo ""

echo "== Pattern: \"*:2:1460:\" =="
echo "This pattern means:"
echo "  - ANY window size is allowed (*)"
echo "  - ONLY option 2 (MSS) should be present, and NO OTHER options"
echo "  - MSS value MUST be 1460"
echo "  - NO window scale value (implied by trailing colon)"
echo "  - This does NOT match packets with option format like \"2-3-1\" or any other combination"
echo ""

echo "== Pattern: \"*:2:1460:*\" =="
echo "This pattern means:"
echo "  - ANY window size is allowed (*)"
echo "  - ONLY option 2 (MSS) should be present, and NO OTHER options"
echo "  - MSS value MUST be 1460"
echo "  - ANY window scale value is allowed (*)"
echo "  - This is semantically invalid because we require option 2 only, but also want a window scale"
echo "    which would be specified by option 3"
echo ""

echo "== Pattern: \"*:*:1460:7\" =="
echo "This pattern means:"
echo "  - ANY window size is allowed (*)"
echo "  - ANY options are allowed (*) - doesn't matter which ones are present"
echo "  - MSS value MUST be 1460 (implies option 2 must be present)"
echo "  - Window scale value MUST be 7 (implies option 3 must be present)"
echo ""

echo "== Pattern: \"64240:2-4-8-1-3:1460:7\" =="
echo "This pattern means:"
echo "  - Window size MUST be 64240"
echo "  - Options MUST include kinds 2,4,8,1,3 in that order"
echo "  - MSS value MUST be 1460"
echo "  - Window scale value MUST be 7"
echo "  - This is NOT matched by \"*:2:1460:\" pattern because the options don't match"
echo "    (\"*:2:1460:\" requires exactly option 2 and nothing else)"
echo ""

echo "Understanding these patterns is crucial for correctly configuring the filter."