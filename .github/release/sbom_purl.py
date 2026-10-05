"""Complete the root purl through the hash-locked CycloneDX public model API."""

import json
import sys
from pathlib import Path

from cyclonedx.model.bom import Bom
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from packageurl import PackageURL

path = Path(sys.argv[1])
bom = Bom.from_json(data=json.loads(path.read_text(encoding="utf-8")))
if bom is None or bom.metadata.component is None or not bom.metadata.component.version:
    raise ValueError("A versioned root component is required before adding its purl")
root = bom.metadata.component
root.purl = PackageURL(type="pypi", name=root.name, version=root.version)
content = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6).output_as_string(indent=2)
errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(content)
if errors:
    raise ValueError(f"Completed SBOM does not validate: {errors}")
path.write_text(content + "\n", encoding="utf-8", newline="\n")
