package ghidra.openai

import ghidra.app.ExamplesPluginPackage
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.app.plugin.core.decompile.actions.GetFunctionSummaryAction
import ghidra.app.services.ProgramManager
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import io.ktor.client.plugins.HttpTimeout

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "GhidraOpenAI",
    category = PluginCategoryNames.MISC,
    shortDescription = "OpenAI Integration",
    description = "Proof of Concept Plugin for OpenAI API integration",
    servicesProvided = [OpenAIServiceInterface::class],
) //@formatter:on
class OpenAIPlugin(tool: PluginTool?) : ProgramPlugin(tool) {
    init {
        setupOptions()
        setupServices()
        registerActions()
//        state.tool.getService(ghidra.openai.OpenAIServiceInterface::class.java)


    }

    private fun registerActions() {
        tool.addAction(GetFunctionSummaryAction())
    }

    private fun setupServices() {
        HttpTimeout

        val options = tool.getOptions("OpenAI")
        val apiKey: String? = options.getString("API_KEY", null)
        // TODO: Cleanly handle lack of configured API key
        registerServiceProvided(OpenAIServiceInterface::class.java, OpenAIService(apiKey!!, tool))
    }

    private fun setupOptions() {
        // Create  Ghidra Tool options to save the API key
        val options = tool.getOptions("OpenAI")
        options.registerOption("API_KEY", "", null, "OpenAI API Key")
        val modelOptions = options.getOptions("Model")

        // Parameters taken from https://github.com/JusticeRage/Gepetto/blob/main/gepetto.py#L188-L194
        modelOptions.registerOption("MODEL", "text-davinci-003", null, "OpenAI Model")
        // Temperature Option
        modelOptions.registerOption("TEMPERATURE", 0.6, null, "Temperature")
        // TopP Option
        modelOptions.registerOption("TOP_P", 1.0, null, "TopP")
        // Max Tokens Option
        modelOptions.registerOption("MAX_TOKENS", 2500, null, "Max Tokens")
        // Prompt option
        modelOptions.registerOption("PROMPT",
            "Can you explain what the following C function does and suggest a better name for it?",
            null, "Prompt")

    }
}