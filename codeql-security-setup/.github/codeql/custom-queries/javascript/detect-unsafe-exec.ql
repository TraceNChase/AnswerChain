/**
 * @name Unsafe use of exec
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @id js/unsafe-exec
 * @tags security
 *       external/cwe/cwe-078
 */

import javascript
import DataFlow::PathGraph

class UnsafeExecConfig extends TaintTracking::Configuration {
  UnsafeExecConfig() { this = "UnsafeExecConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SystemCommandExecution exec | 
      sink = exec.getACommandArgument()
    )
  }
}

from UnsafeExecConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "Potential command injection from $@.", source, "user-provided value"
