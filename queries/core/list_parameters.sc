// List parameters of a specific method
cpg.method.name("{{ method_name }}")
  .map(m => (m.name, m.parameter.map(p => (p.name, p.typeFullName, p.index)).l))
