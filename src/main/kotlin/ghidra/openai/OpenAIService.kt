package ghidra.openai

import com.aallam.openai.api.completion.CompletionRequest
import com.aallam.openai.api.completion.TextCompletion
import com.aallam.openai.api.model.ModelId
import com.aallam.openai.client.OpenAI
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI
import ghidra.framework.plugintool.PluginTool
import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.listing.Function
import kotlinx.coroutines.runBlocking

class OpenAIService(val apiKey: String, val tool: PluginTool): OpenAIServiceInterface {
    override fun getEngine(): OpenAI {
        return OpenAI(apiKey)
    }


    override fun getFunctionSummaryShort(function: Function): String {
        val openAI = this.getEngine()



        // Get the decompiled function via the Ghidra API
        val funcText = FlatDecompilerAPI(FlatProgramAPI(function.program)).decompile(function, 0)


        val modelOptions = tool.getOptions("OpenAI").getOptions("Model")

        val basePrompt = modelOptions.getString("PROMPT", "Can you explain what the following C function does and suggest a better name for it?")

        val prompt = basePrompt + '\n' + funcText

        // Get model options
        val completionRequest = CompletionRequest(
            model = ModelId(modelOptions.getString("MODEL", "text-davinci-003")),
            prompt = prompt,
            temperature = modelOptions.getDouble("TEMPERATURE", 0.6),
            topP = modelOptions.getDouble("TOP_P", 1.0),
            maxTokens = modelOptions.getInt("MAX_TOKENS", 2500),
        )

        val completion: TextCompletion = runBlocking {
            openAI.completion(completionRequest)
        }
        val result = completion.choices[0].text
        return result
    }


}