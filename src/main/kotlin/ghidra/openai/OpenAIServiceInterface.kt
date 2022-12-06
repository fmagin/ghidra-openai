package ghidra.openai

import com.aallam.openai.client.OpenAI
import ghidra.framework.plugintool.ServiceInfo
import ghidra.program.model.listing.Function

@ServiceInfo(defaultProvider = [OpenAIPlugin::class])
interface OpenAIServiceInterface {
    fun getEngine(): OpenAI?
    fun getFunctionSummaryShort(function: Function): String
}

