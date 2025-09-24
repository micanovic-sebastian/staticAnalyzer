package org.example.analyzer;

import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.VariableTree;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Manages the logic for a simple taint analysis.
 * It tracks variables that are "tainted" by untrusted sources and
 * checks if they flow into sensitive "sinks".
 */
public class TaintAnalyzer {

    private final Set<String> taintedVariables = new HashSet<>();

    /**
     * Checks if a method call is a known taint source. If so, it taints the
     * variable that the result is assigned to.
     *
     * @param assignmentNode The variable declaration (e.g., "String cmd = ...").
     * @param sourceMethod The method call on the right side of the assignment.
     */
    public void trackSource(VariableTree assignmentNode, MethodInvocationTree sourceMethod) {
        String methodName = sourceMethod.getMethodSelect().toString();

        if (DenyList.TAINT_SOURCES.stream().anyMatch(methodName::endsWith)) {
            String variableName = assignmentNode.getName().toString();
            taintedVariables.add(variableName);
            System.out.println("Tainted variable found: " + variableName); // For debugging
        }
    }

    /**
     * Propagates taint from one variable to another during an assignment.
     *
     * @param newVariable The variable being assigned to (e.g., "b" in "String b = a;").
     * @param assignedVariable The variable being assigned from (e.g., "a" in "String b = a;").
     */
    public void propagateTaint(VariableTree newVariable, ExpressionTree assignedVariable) {
        if (assignedVariable instanceof IdentifierTree) {
            String assignedVarName = ((IdentifierTree) assignedVariable).getName().toString();
            if (taintedVariables.contains(assignedVarName)) {
                String newVarName = newVariable.getName().toString();
                taintedVariables.add(newVarName);
            }
        }
    }

    /**
     * Checks if a method call is a sensitive sink being called with a tainted argument.
     *
     * @param sinkMethod The method call to check.
     * @return An Optional containing a violation message if a tainted sink is found.
     */
    public Optional<String> analyzeSink(MethodInvocationTree sinkMethod) {
        String methodName = sinkMethod.getMethodSelect().toString();

        if (DenyList.SENSITIVE_SINKS.stream().anyMatch(methodName::endsWith)) {
            for (ExpressionTree arg : sinkMethod.getArguments()) {
                if (arg instanceof IdentifierTree) {
                    String argName = ((IdentifierTree) arg).getName().toString();
                    if (taintedVariables.contains(argName)) {
                        return Optional.of(String.format(
                            "CRITICAL: Tainted variable '%s' used in sensitive sink '%s'",
                            argName, methodName
                        ));
                    }
                }
            }
        }
        return Optional.empty();
    }
}