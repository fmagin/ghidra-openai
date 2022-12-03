/* ###
 * IP: GHIDRA
 *
 * Example plugin converted to Kotlin by IntelliJ IDEA, then cleaned and made more idiomatic by Florian Magin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.examples

import docking.ActionContext
import docking.action.DockingAction
import docking.action.KeyBindingData
import docking.action.MenuData
import docking.action.ToolBarData
import ghidra.app.ExamplesPluginPackage
import ghidra.app.events.ProgramLocationPluginEvent
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.app.services.ProgramManager
import ghidra.framework.options.SaveState
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.listing.Program
import ghidra.util.HelpLocation
import ghidra.util.Msg
import resources.ResourceManager
import java.awt.Event
import java.awt.event.KeyEvent
import javax.swing.JOptionPane
import javax.swing.KeyStroke

/**
 * Class description goes here
 *
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ExamplesPluginPackage.NAME,
    category = PluginCategoryNames.EXAMPLES,
    shortDescription = "Kitchen Sink hello (Kotlin)",
    description = "Sample plugin to demonstrate services and action enablement, hello world. (Kotlin)",
    servicesProvided = [HelloWorldService::class],
    servicesRequired = [ProgramManager::class],
    eventsProduced = [ProgramLocationPluginEvent::class]
) //@formatter:on
class KitchenSinkPlugin(tool: PluginTool?) : ProgramPlugin(tool, false, false) {
    private var helloProgramAction: DockingAction? = null
    private var program: Program? = null

    /**
     * Constructor
     */
    init {

        // set up list of services.
        setupServices()

        // set up list of actions.
        setupActions()
    }

    private fun setupServices() {
        registerServiceProvided(
            HelloWorldService::class.java,
            object : HelloWorldService {
                override fun sayHello() {
                    announce("Hello")
                }
            })
    }

    private fun setupActions() {
        var action: DockingAction = object : DockingAction("Hello World", name) {
            override fun actionPerformed(context: ActionContext) {
                Msg.info(this, "Hello World:: action")
                announce("Hello World")
            }
        }
        val helloGroup = "Hello"

        with (action) {
            isEnabled = true
            val prevImage = ResourceManager.loadImage(PREV_IMAGE)
            menuBarData = MenuData(arrayOf("Misc", "Hello World"), prevImage, helloGroup)
            popupMenuData = MenuData(arrayOf("Hello World"), prevImage, helloGroup)
            keyBindingData = KeyBindingData(KeyStroke.getKeyStroke('H'.code, Event.CTRL_MASK))
            toolBarData = ToolBarData(prevImage, helloGroup)
            description = "Hello World"
            setHelpLocation(HelpLocation("SampleHelpTopic", "KS_Hello_World"))
            tool.addAction(action)
        }

        action = object : DockingAction("Hello Program", name) {
            override fun actionPerformed(context: ActionContext) {
                Msg.info(this, "Hello Program:: action")
                sayHelloProgram()
            }
        }
        with (action) {
            isEnabled = true
            val nextImage = ResourceManager.loadImage(NEXT_IMAGE)
            menuBarData = MenuData(arrayOf("Misc", "Hello Program"), nextImage, helloGroup)
            keyBindingData = KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_P, Event.CTRL_MASK))
            toolBarData = ToolBarData(nextImage, helloGroup)
            description = "Hello Program"
            setHelpLocation(HelpLocation("SampleHelpTopic", "KS_Hello_Program"))
            tool.addAction(action)
        }

        // remember this action so I can enable/disable it later
        helloProgramAction = action
    }

    override fun programActivated(activatedProgram: Program) {
        helloProgramAction!!.isEnabled = true
        program = activatedProgram
    }

    override fun programDeactivated(deactivatedProgram: Program) {
        if (program === deactivatedProgram) {
            helloProgramAction!!.isEnabled = false
            program = null
        }
    }

    protected fun sayHelloProgram() {
        if (program != null){
            // Kotlin infers that program could have been nulled again, so we have to assert it is not null with !!
            // at the risk of maybe throwing a null pointer exception
            announce("Hello ${program!!.name}")
        }

    }

    protected fun announce(message: String?) {
        JOptionPane.showMessageDialog(
            null, message, "Hello World",
            JOptionPane.INFORMATION_MESSAGE
        )
    }

    /**
     * If your plugin maintains configuration state, you must save that state information
     * to the SaveState object in this method.  For example, the Code Browser can be configured
     * to show fields in different colors.  This is the method where that type
     * information is saved.
     */
    override fun writeConfigState(saveState: SaveState) {}

    /**
     * If your plugin maintains configuration state, this is where you read it
     * back in.
     */
    override fun readConfigState(saveState: SaveState) {}

    // Companion objects are the "static" part of a JVM class, i.e. present without needing to instantiate the class
    companion object {
        private const val NEXT_IMAGE = "images/right.png"
        private const val PREV_IMAGE = "images/left.png"
    }


}