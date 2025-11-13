// Check if one method can reach another through the call graph
{
  val source = cpg.method.name("{{ source_method }}").l
  val target = cpg.method.name("{{ target_method }}").l
  val reachable = if (source.nonEmpty && target.nonEmpty) {
    val targetName = target.head.name
    var visited = Set[String]()
    var toVisit = scala.collection.mutable.Queue[io.shiftleft.codepropertygraph.generated.nodes.Method]()
    toVisit.enqueue(source.head)
    var found = false
    while (toVisit.nonEmpty && !found) {
      val current = toVisit.dequeue()
      val currentName = current.name
      if (!visited.contains(currentName)) {
        visited = visited + currentName
        val callees = current.call.callee.l
        for (callee <- callees) {
          val calleeName = callee.name
          if (calleeName == targetName) {
            found = true
          } else if (!visited.contains(calleeName) && !calleeName.startsWith("<operator>")) {
            toVisit.enqueue(callee)
          }
        }
      }
    }
    found
  } else false
  List(reachable).toJsonPretty
}
