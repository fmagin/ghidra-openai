package ghidra.app.plugin.core.decompile.actions

import GhidraJupyterKotlin.extensions.misc.runTransaction
import docking.DialogComponentProvider
import docking.action.MenuData
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.app.util.HelpTopics
import ghidra.openai.OpenAIServiceInterface
import ghidra.util.HelpLocation
import ghidra.util.task.Task
import ghidra.util.task.TaskLauncher
import ghidra.util.task.TaskMonitor


class GetFunctionSummaryAction: AbstractDecompilerAction("Get Function Summary"){

    init {
        helpLocation = HelpLocation(HelpTopics.DECOMPILER, "ActionEditSignature")
        popupMenuData = MenuData(arrayOf("Get and apply Function Summary via OpenAI"), "Decompile")
    }

    override fun isEnabledForDecompilerContext(context: DecompilerActionContext?): Boolean {
        return true
    }

    override fun decompilerActionPerformed(context: DecompilerActionContext?) {
        val task = GetFunctionSummaryTask(context!!)
        TaskLauncher(task, context.tool.toolFrame)
    }

}

class GetFunctionSummaryTask(val context: DecompilerActionContext): Task("Get Function Summary", false, false, false) {
    override fun run(taskMonitor: TaskMonitor?) {
        val aiSrv = context.tool.getService(OpenAIServiceInterface::class.java)
        val summary = aiSrv.getFunctionSummaryShort(context.function)
        context.program.runTransaction("Apply OpenAI Function Summary"){
            context.function.comment = summary
        }
    }

}