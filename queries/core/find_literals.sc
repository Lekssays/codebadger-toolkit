// Find literal values in the code with optional filters// Find literal values in the code

cpg.literal// Parameters: pattern (optional), literal_type (optional), limit

  {%- if pattern %}

  .code("{{ pattern }}")cpg.literal

  {%- endif %}  {%- if pattern %}

  {%- if literal_type %}  .code("{{ pattern }}")

  .typeFullName(".*{{ literal_type }}.*")  {%- endif %}

  {%- endif %}  {%- if literal_type %}

  .map(lit => (lit.code, lit.typeFullName, lit.filename, lit.lineNumber.getOrElse(-1), lit.method.name))  .typeFullName(".*{{ literal_type }}.*")

  .take({{ limit }})  {%- endif %}

  .map(lit => (lit.code, lit.typeFullName, lit.filename, lit.lineNumber.getOrElse(-1), lit.method.name))
  .take({{ limit }})
