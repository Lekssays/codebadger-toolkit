// Get call graph for a method at specified depth and direction// Generate call graph for a method

{%- if direction == "outgoing" %}// Parameters: method_name, depth, direction (outgoing or incoming), limit

  {%- if depth == 1 %}

cpg.method.name("{{ method_name }}").headOption.map(m => {%- if direction == "outgoing" %}

  m.call.callee.filterNot(_.name.startsWith("<operator>")).map(c => (m.name, c.name, 1)).l{%- if depth == 1 %}

).getOrElse(List()).toJsonPretty// Depth 1 outgoing calls (direct callees)

  {%- else %}cpg.method.name("{{ method_name }}").headOption.map(m => 

{  m.call.callee.filterNot(_.name.startsWith("<operator>")).map(c => (m.name, c.name, 1)).l

  val rootMethod = cpg.method.name("{{ method_name }}").l).getOrElse(List()).toJsonPretty

  if (rootMethod.nonEmpty) {{%- else %}

    val rootName = rootMethod.head.name// Depth {{ depth }} outgoing calls with BFS

    var allCalls = scala.collection.mutable.ListBuffer[(String, String, Int)](){

    var toVisit = scala.collection.mutable.Queue[(io.shiftleft.codepropertygraph.generated.nodes.Method, Int)]()  val rootMethod = cpg.method.name("{{ method_name }}").l

    var visited = Set[String]()  if (rootMethod.nonEmpty) {

    toVisit.enqueue((rootMethod.head, 0))    val rootName = rootMethod.head.name

    while (toVisit.nonEmpty) {    var allCalls = scala.collection.mutable.ListBuffer[(String, String, Int)]()

      val (current, currentDepth) = toVisit.dequeue()    var toVisit = scala.collection.mutable.Queue[(io.shiftleft.codepropertygraph.generated.nodes.Method, Int)]()

      val currentName = current.name    var visited = Set[String]()

      if (!visited.contains(currentName) && currentDepth < {{ depth }}) {    toVisit.enqueue((rootMethod.head, 0))

        visited = visited + currentName    while (toVisit.nonEmpty) {

        val callees = current.call.callee.l      val (current, currentDepth) = toVisit.dequeue()

        for (callee <- callees) {      val currentName = current.name

          val calleeName = callee.name      if (!visited.contains(currentName) && currentDepth < {{ depth }}) {

          if (!calleeName.startsWith("<operator>")) {        visited = visited + currentName

            allCalls += ((currentName, calleeName, currentDepth + 1))        val callees = current.call.callee.l

            if (!visited.contains(calleeName)) {        for (callee <- callees) {

              toVisit.enqueue((callee, currentDepth + 1))          val calleeName = callee.name

            }          if (!calleeName.startsWith("<operator>")) {

          }            allCalls += ((currentName, calleeName, currentDepth + 1))

        }            if (!visited.contains(calleeName)) {

      }              toVisit.enqueue((callee, currentDepth + 1))

    }            }

    allCalls.toList          }

  } else List[(String, String, Int)]()        }

}.toJsonPretty      }

  {%- endif %}    }

{%- else %}    allCalls.toList

  {%- if depth == 1 %}  } else List[(String, String, Int)]()

cpg.method.name("{{ method_name }}").headOption.map(m => }.toJsonPretty

  m.caller.filterNot(_.name.startsWith("<operator>")).map(c => (c.name, m.name, 1)).l{%- endif %}

).getOrElse(List()).toJsonPretty{%- else %}

  {%- else %}{%- if depth == 1 %}

{// Depth 1 incoming calls (direct callers)

  val targetMethod = cpg.method.name("{{ method_name }}").lcpg.method.name("{{ method_name }}").headOption.map(m => 

  if (targetMethod.nonEmpty) {  m.caller.filterNot(_.name.startsWith("<operator>")).map(c => (c.name, m.name, 1)).l

    val targetName = targetMethod.head.name).getOrElse(List()).toJsonPretty

    var allCallers = scala.collection.mutable.ListBuffer[(String, String, Int)](){%- else %}

    var toVisit = scala.collection.mutable.Queue[(io.shiftleft.codepropertygraph.generated.nodes.Method, Int)]()// Depth {{ depth }} incoming calls with BFS

    var visited = Set[String](){

    val directCallers = targetMethod.head.caller.l  val targetMethod = cpg.method.name("{{ method_name }}").l

    for (caller <- directCallers) {  if (targetMethod.nonEmpty) {

      allCallers += ((caller.name, targetName, 1))    val targetName = targetMethod.head.name

      toVisit.enqueue((caller, 1))    var allCallers = scala.collection.mutable.ListBuffer[(String, String, Int)]()

    }    var toVisit = scala.collection.mutable.Queue[(io.shiftleft.codepropertygraph.generated.nodes.Method, Int)]()

    while (toVisit.nonEmpty) {    var visited = Set[String]()

      val (current, currentDepth) = toVisit.dequeue()    val directCallers = targetMethod.head.caller.l

      val currentName = current.name    for (caller <- directCallers) {

      if (!visited.contains(currentName) && currentDepth < {{ depth }}) {      allCallers += ((caller.name, targetName, 1))

        visited = visited + currentName      toVisit.enqueue((caller, 1))

        val incomingCallers = current.caller.l    }

        for (caller <- incomingCallers) {    while (toVisit.nonEmpty) {

          val callerName = caller.name      val (current, currentDepth) = toVisit.dequeue()

          if (!callerName.startsWith("<operator>")) {      val currentName = current.name

            allCallers += ((callerName, targetName, currentDepth + 1))      if (!visited.contains(currentName) && currentDepth < {{ depth }}) {

            if (!visited.contains(callerName)) {        visited = visited + currentName

              toVisit.enqueue((caller, currentDepth + 1))        val incomingCallers = current.caller.l

            }        for (caller <- incomingCallers) {

          }          val callerName = caller.name

        }          if (!callerName.startsWith("<operator>")) {

      }            allCallers += ((callerName, targetName, currentDepth + 1))

    }            if (!visited.contains(callerName)) {

    allCallers.toList              toVisit.enqueue((caller, currentDepth + 1))

  } else List[(String, String, Int)]()            }

}.toJsonPretty          }

  {%- endif %}        }

{%- endif %}      }

    }
    allCallers.toList
  } else List[(String, String, Int)]()
}.toJsonPretty
{%- endif %}
{%- endif %}
