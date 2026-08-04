/**
 * @name Missing minimum-length or nonnegative check before protocol parser use
 * @description Detects packet length or offset values used in protocol parsing without an apparent minimum-length or nonnegative guard in the same function.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id freevrg/missing-minimum-length-check-on-network-protocol-packet
 * @tags security
 */

import cpp
import semmle.code.cpp.commons.Assertions

Function enclosingFunction(Element e) {
  exists(Expr expr | e = expr and result = expr.getEnclosingFunction())
  or
  exists(Stmt stmt | e = stmt and result = stmt.getEnclosingFunction())
}

predicate beforeUse(Locatable guard, Element useSite) {
  guard.getLocation().getFile() = useSite.getLocation().getFile() and
  guard.getLocation().getStartLine() <= useSite.getLocation().getStartLine()
}

predicate accessesVariable(Expr tree, Variable value) {
  exists(VariableAccess access |
    tree.getAChild*() = access and
    access.getTarget() = value
  )
}

predicate isIntegralVariable(Variable value) {
  value.getType().getUnspecifiedType() instanceof IntegralType
}

predicate hasProtocolLengthName(Variable value) {
  value.getName().regexpMatch("(?i).*(len|length|alen|offset|off|pos|ptr|pointed_len).*")
}

predicate hasDirectLengthName(Variable value) {
  value.getName().regexpMatch("(?i)^(len|length|packet_len|packet_length|msg_len|message_len|payload_len|data_len)$")
}

predicate isProtocolParsingFunction(Function function) {
  function.getName().regexpMatch("(?i).*(parse|decode|packet|response|request|attr|protocol|radius|dhcp|domain).*" )
}

predicate isAssignedFromParserCall(Variable value, Function function) {
  exists(AssignExpr assign, VariableAccess lhs, FunctionCall call |
    assign.getEnclosingFunction() = function and
    assign.getLValue() = lhs and
    lhs.getTarget() = value and
    assign.getRValue() = call
  )
}

predicate isAssignedFromPacketBytes(Variable value, Function function) {
  exists(AssignExpr assign, VariableAccess lhs, ArrayExpr read |
    assign.getEnclosingFunction() = function and
    assign.getLValue() = lhs and
    lhs.getTarget() = value and
    assign.getRValue().getAChild*() = read
  )
}

predicate isPacketLengthVariable(Variable value, Function function) {
  isIntegralVariable(value) and
  hasProtocolLengthName(value) and
  (
    isAssignedFromParserCall(value, function) or
    hasDirectLengthName(value) and isAssignedFromPacketBytes(value, function) or
    isProtocolParsingFunction(function) and
    value instanceof Parameter
  )
}

predicate isLengthArithmeticAssignment(Variable value, Element useSite) {
  exists(Assignment assign |
    useSite = assign and
    accessesVariable(assign.getRValue(), value) and
    not accessesVariable(assign.getLValue(), value)
  )
}

predicate isLengthControlledLoop(Variable value, Element useSite) {
  exists(Loop loop |
    useSite = loop and
    accessesVariable(loop.getCondition(), value) and
    (
      exists(ArrayExpr access | loop.getStmt().getAChild*() = access) or
      exists(FunctionCall call | loop.getStmt().getAChild*() = call)
    )
  )
}

predicate isLengthSensitiveCall(Variable value, Element useSite) {
  exists(FunctionCall call, Expr argument |
    useSite = call and
    argument = call.getAnArgument() and
    accessesVariable(argument, value) and
    call.getTarget().getName().regexpMatch("(?i).*(attr|parse|read|get|copy|mem|digest|update).*")
  )
}

predicate isLengthIndexUse(Variable value, Element useSite) {
  exists(ArrayExpr access |
    useSite = access and
    accessesVariable(access.getArrayOffset(), value)
  )
}

predicate isParserUse(Variable value, Element useSite) {
  isLengthArithmeticAssignment(value, useSite) or
  isLengthControlledLoop(value, useSite) or
  isLengthSensitiveCall(value, useSite) or
  isLengthIndexUse(value, useSite)
}

predicate isMinimumThreshold(Expr threshold) {
  exists(Literal literal |
    threshold.getAChild*() = literal and
    not literal instanceof TextLiteral and
    not literal instanceof LabelLiteral
  ) or
  threshold.getAChild*() instanceof SizeofOperator or
  exists(VariableAccess access |
    threshold.getAChild*() = access and
    access.getTarget().getName().regexpMatch("(?i)^(POS_|MIN|HEADER|HDR|.*_MIN|.*_HEADER).*")
  )
}

predicate isMinimumViolation(RelationalOperation comparison, Variable value) {
  (
    accessesVariable(comparison.getLeftOperand(), value) and
    not accessesVariable(comparison.getRightOperand(), value) and
    isMinimumThreshold(comparison.getRightOperand()) and
    comparison.getOperator() = ["<", "<="]
  )
  or
  (
    accessesVariable(comparison.getRightOperand(), value) and
    not accessesVariable(comparison.getLeftOperand(), value) and
    isMinimumThreshold(comparison.getLeftOperand()) and
    comparison.getOperator() = [">", ">="]
  )
}

predicate isValidMinimum(RelationalOperation comparison, Variable value) {
  (
    accessesVariable(comparison.getLeftOperand(), value) and
    not accessesVariable(comparison.getRightOperand(), value) and
    isMinimumThreshold(comparison.getRightOperand()) and
    comparison.getOperator() = [">", ">="]
  )
  or
  (
    accessesVariable(comparison.getRightOperand(), value) and
    not accessesVariable(comparison.getLeftOperand(), value) and
    isMinimumThreshold(comparison.getLeftOperand()) and
    comparison.getOperator() = ["<", "<="]
  )
}

predicate containsMinimumViolation(Expr condition, Variable value) {
  exists(RelationalOperation comparison |
    condition.getAChild*() = comparison and
    isMinimumViolation(comparison, value)
  )
}

predicate containsValidMinimum(Expr condition, Variable value) {
  exists(RelationalOperation comparison |
    condition.getAChild*() = comparison and
    isValidMinimum(comparison, value)
  )
}

predicate branchReturns(Stmt branch) {
  branch instanceof ReturnStmt or
  exists(ReturnStmt ret | branch.getAChild*() = ret)
}

predicate isInside(Stmt branch, Element useSite) {
  useSite = branch or branch.getAChild*() = useSite
}

predicate hasRelevantGuard(Variable value, Element useSite) {
  exists(IfStmt guard |
    guard.getEnclosingFunction() = enclosingFunction(useSite) and
    beforeUse(guard, useSite) and
    containsMinimumViolation(guard.getCondition(), value) and
    branchReturns(guard.getThen())
  )
  or
  exists(IfStmt guard |
    guard.getEnclosingFunction() = enclosingFunction(useSite) and
    containsValidMinimum(guard.getCondition(), value) and
    isInside(guard.getThen(), useSite)
  )
  or
  exists(Assertion assertion |
    assertion.getAsserted().getEnclosingFunction() = enclosingFunction(useSite) and
    beforeUse(assertion, useSite) and
    containsValidMinimum(assertion.getAsserted(), value)
  )
  or
  exists(FunctionCall assertCall |
    assertCall.getEnclosingFunction() = enclosingFunction(useSite) and
    beforeUse(assertCall, useSite) and
    assertCall.getTarget().hasName("assert") and
    containsValidMinimum(assertCall.getArgument(0), value)
  )
}

from Variable value, Element useSite
where
  isPacketLengthVariable(value, enclosingFunction(useSite)) and
  isParserUse(value, useSite) and
  not hasRelevantGuard(value, useSite)
select useSite,
  "Packet length or offset '" + value.getName() +
  "' is used in protocol parsing without an apparent minimum-length or nonnegative guard."
