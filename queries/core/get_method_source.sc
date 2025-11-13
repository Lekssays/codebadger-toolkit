// Get the source code metadata of a specific method// Get source code for a specific method

cpg.method.name("{{ method_name }}")// Parameters: method_name, filename (optional)

  {%- if filename %}

  .filename(".*{{ filename }}.*")cpg.method.name("{{ method_name }}")

  {%- endif %}  {%- if filename %}

  .map(m => (m.name, m.filename, m.lineNumber.getOrElse(-1), m.lineNumberEnd.getOrElse(-1)))  .filename(".*{{ filename }}.*")

  {%- endif %}
  .map(m => (m.name, m.filename, m.lineNumber.getOrElse(-1), m.lineNumberEnd.getOrElse(-1)))
  .toJsonPretty
