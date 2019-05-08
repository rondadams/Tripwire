SYNOPSIS

  Update Tripwire Enterprise Node Descriptions with the latest version info using API.

DESCRIPTION

  This script will:
  1) Prompt for TE user credentials
  2) Connect to the TE API
  3) Query all nodes for the specified name and tag set (optional)
  4) Fetch list of nodes and properties
  5) Update (replace) the description with new version info contained in Make, Model, Version fields.
