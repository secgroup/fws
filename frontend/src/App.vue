<template>
<div id="main">
  <!-- NAVBAR -->
  <b-navbar type="is-light" :shadow="true">
    <template slot="brand">
      <b-navbar-item tag="div">
        <b-icon pack="fa" icon="fire"></b-icon>
        <b>FWS</b>
      </b-navbar-item>
    </template>
    <template slot="start">
      <b-tabs class="navbar-item" type="is-toggle" v-model="current_mode_idx">
        
        <b-tab-item icon="search" label="Query"></b-tab-item>
        <b-tab-item icon="cog" label="Compiler"></b-tab-item>
      </b-tabs>
    </template>
    
    <template slot="end">
      <b-navbar-item tag="div">
        <div class="buttons">
          <b-button icon-left="play" type="is-primary" v-if="getCurrentMode() == 'query'" @click="queryRun" :disabled="isWorking">Run</b-button>
          
          <b-button icon-left="save" type="is-primary" v-if="getCurrentMode() == 'compiler'" disabled>Save</b-button>
          <b-button icon-left="folder-open" type="is-primary" v-if="getCurrentMode() == 'compiler'">Load</b-button>
          <b-button icon-left="cogs" type="is-primary" v-if="getCurrentMode() == 'compiler'" disabled>Compile</b-button>
        </div>
      </b-navbar-item>
    </template>
  </b-navbar>
  <!-- NAVBAR END -->

  <div class="components-container">
   <split-pane :min-percent='10' v-on:resize="resize" :max-percent='10' :default-percent='10' split="vertical">
     <template slot="paneL">
       <div class="panel left-panel">

          <p class="panel-heading">
            Policies
          </p>
         
          <div class="panel-block">
            <b-button icon-left="folder-open" class="button is-link is-outlined is-fullwidth" @click="loadPolicy">
              Load Policy
            </b-button>
          </div>

          <a class="panel-block" v-for="item in loaded_policies" :key="item">
            <span class="panel-icon">
              <i class="fa fa-file" aria-hidden="true"></i>
            </span> {{ item }}
          </a>

          <div class="panel-block has-text-centered is-block" v-if='loaded_policies.length == 0'>
            <i class="fa fa-frown" aria-hidden="true"></i><br>
            No results
          </div>

          
       </div>
      
     </template>
     <template slot="paneR">

       <div class="fullheight" v-if="getCurrentMode() == 'compiler'">

         

         <div class="fullheight">
           <div class="container mt-5 pt-5">

             <table class="fws-table singleline">
               <thead><tr>
                   <td><b>Source IP</b></td><td><b>Source Port</b></td>
                   <!--<td><b>SNAT IP</b></td><td><b>SNAT Port</b></td><td><b>DNAT IP</b></td><td><b>DNAT Port</b>-->
                   <td><b>Destination IP</b></td><td><b>Destination Port</b></td>
                   <td><b>Source MAC</b></td><td><b>Destination MAC</b></td>
                   <td><b>Protocol</b></td><td><b>State</b></td>
                   <td>
                     <b-icon pack="fa" icon="wrench" class="has-text-grey-light"/>
                     <b-tooltip label="Add Row">
                       <span class="fa fa-plus-circle"></span>
                     </b-tooltip>
                   </td>
               </tr></thead>
               <tr v-for="(field,index) in fwstable" v-bind:key="index">
                   <td><contenteditable :value="p2h(field.srcIp)"    @update:value="v => field.srcIp    = h2p(v)" /></td>
                   <td><contenteditable :value="p2h(field.srcPort)"  @update:value="v => field.srcPort  = h2p(v)" /></td>
                   <td><contenteditable :value="p2h(field.dstIp)"    @update:value="v => field.dstIp    = h2p(v)" /></td>
                   <td><contenteditable :value="p2h(field.dstPort)"  @update:value="v => field.dstPort  = h2p(v)" /></td>
                   <td><contenteditable :value="p2h(field.srcMAC)"   @update:value="v => field.srcMAC   = h2p(v)" /></td>
                   <td><contenteditable :value="p2h(field.dstMAC)"   @update:value="v => field.dstMAC   = h2p(v)" /></td>
                   <td><contenteditable :value="p2h(field.protocol)" @update:value="v => field.protocol = h2p(v)" /></td>
                   <td><contenteditable :value="p2h(field.state)"    @update:value="v => field.state    = h2p(v)" /></td>
                   <td style="text-align:center; vertical-align: middle; background: #f5f5f5;">
                     <b-tooltip label="Delete Row">
                         <span class="fa fa-times-circle" @click="fwstable.splice(index,1)"></span>
                     </b-tooltip>
                   </td>
                 </tr>
             </table>

             <p style="font-face: monospace" class="mb-4">{{ fwstable }}</p>
             
           </div>
         </div>
         
         
         <div class="empty-output" v-if=false> <!-- TODO v-if="no-output" -->
           <b-message has-icon icon="info" class="empty-output-message" >
               <p><b>No output.</b></p>
               <p>Help:</p>
               <ol class="pl-4">
                 <li>Load a policy file in the "Policies" panel.</li>
                 <li>Select a policy file or "Load" a previously saved table file.</li>
                 <li>Edit the tables.</li>
                 <li>Click "Compile" and select the target langauge.</li>
               </ol>
             </b-message>
         </div>
       </div>
       
       <split-pane :min-percent='20'  v-on:resize="resize" :default-percent='40'  split="vertical"  v-if="getCurrentMode() == 'query'">
         <template slot="paneL">
           <MonacoEditor class="editor mt-2" style="height: calc(100% - 2.00rem)" theme="vs" v-model="query_code" language="sql" @editorDidMount="editorDidMount" :options="monaco_options"></MonacoEditor>
         </template>
         <template slot="paneR">

           <div class="fullheight" style="height: 100%; overflow: scroll;" ref="queryOutputContainer" v-if="query_progress">
             <div class="container">
               <pre v-html="query_output" style="background: white; overflow-x: unset;"></pre>
               <b-progress class="mt-3 ml-3 mr-3 mb-5" :value="query_progress" show-value format="percent" v-if="isWorking "></b-progress>
             </div>
         </div>
           
           <div class="empty-output" v-if="!query_progress">
             <b-message has-icon icon="info" class="empty-output-message" >
               <p><b>No output.</b></p>
               <p>Help:</p>
               <ol class="pl-4">
                 <li>Load a policy file in the "Policies" panel.</li>
                 <li>Write your queries (fws script) in the editor.</li>
                 <li>Click "Run".</li>
                 <li>The script output will be shown here.</li>
               </ol>
             </b-message>
           </div>
           
         </template>
       </split-pane>

       
     </template>
   </split-pane>
  </div>
  
  <div class="navbar is-primary statusbar">
    <span v-if=isWorking> <b-icon pack="fa" icon="sync" custom-class="fa-spin" /> [FWS:{{ fws_instance }}] working... </span>
    <span v-else> <b-icon pack="fa" icon="check-circle"/> [FWS:{{ fws_instance }}] ready </span>
  </div>

</div>
</template>

<script>
import MonacoEditor from 'vue-monaco'
import splitPane from 'vue-splitpane'
import contenteditable from './components/contenteditable.vue'

const FWS_URI = "http://172.17.0.2:5095" // ""

export default {

    name: 'App',
    components: {
        MonacoEditor,
        splitPane,
        contenteditable,
    },

    methods: {
        h2p: require('html2plaintext'),
        p2h: v => v.replace(/\n/g, "<br>").replace(/ /g, "&nbsp;"),
        getCurrentMode() {
            return this.modes[this.current_mode_idx]
        },
        editorDidMount(editor) {
            this.editor = editor
        },
        resize() {
            this.editor.layout()
        },
        showError(e) {
            this.$buefy.notification.open({
                message: `Error: ${e}`,
                type: 'is-danger',
                hasIcon: true,
            })
        },
        queryRun() {
            this.isWorking = true;
            this.query_progress = 0.1
            fetch(`${FWS_URI}/${this.fws_instance}/eval`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    'contents': this.query_code
                })
            }).then(async response => {
                let reader = response.body.getReader()
                const decoder = new TextDecoder()
                let progress_regex = new RegExp('\\rSolving: \\[#* *\\] \\( *\\d+/ *\\d+\\) ([0-9\\.]+)%\\r', 'g')
                let partial_bar = new RegExp('\\rSolving:.*', 'g')
                
                let output = ""
                for (;;) {
                    const { value, done } = await reader.read()
                    if (done) break
                    const str = decoder.decode(value)
                    console.log(str)
                    output += str
                    const matches = [...output.matchAll(progress_regex)]
                    console.log(matches)
                    if (matches.length > 0) {
                        this.query_progress = parseFloat(matches[matches.length-1][1]);
                        output = output.replaceAll(progress_regex, '')
                    }
                    this.query_output = output.replaceAll(partial_bar)
                    this.$refs.queryOutputContainer.scrollTo(0, this.$refs.queryOutputContainer.children[0].offsetHeight)
                }
                this.query_output = output
                this.$refs.queryOutputContainer.scrollTo(0, this.$refs.queryOutputContainer.children[0].offsetHeight)
                this.isWorking = false;
            }).catch(e => {this.showError(e); this.isWorking = false})
        },
        loadPolicy() {
            this.showError("Not Implemented!")
        }
    },

    mounted() {
        fetch(`${FWS_URI}/new_repl`).then(b => b.json())
            .then(res => {
                console.log(res)
                this.fws_instance = res['value']
                this.isWorking = false;
            }).catch(this.showError)
    },
    
    data() {
        return {
            current_mode_idx: 0,
            size: 10,
            modes: ['query', 'compiler'],
            monaco_options: {
                tabSize: 4,
                lineNumbers: true,
                lineNumbersMinChars: 1,
                folding: false,
                minimap: { enabled: false },
                automaticLayout: true,
                wordWrap: true,
            },
            editor: null,
            loaded_policies: [],
            isWorking: true,
            fws_instance: null,
            query_code: `p = load_policy(iptables, "examples/policies/iptables.rules", "examples/policies/interfaces_aliases.conf")

synthesis(p) in forward/filter 
`,
            query_output: "",
            query_progress: 0,
            fwstable: [
                {srcIp: "* \\ { \n  10.0.0.0/16\n  192.168.0.0/16 \n}", srcPort: "*", dstIp: "web_server\nssh_server", dstPort: "443", srcMAC: "*", dstMAC: "*", protocol: "tcp", state: "NEW"},
                {srcIp: "*", srcPort: "*", dstIp: "web_server\nssh_server", dstPort: "443", srcMAC: "*", dstMAC: "*", protocol: "tcp", state: "NEW"},
            ]
        };
    }
}
</script>

<style>
.components-container {
  position: relative;
  height: calc( 100vh - 3.75rem - 1.8rem );
}
.splitter-pane-resizer {
  background: none !important;
}
.statusbar {
  min-height: 1.8rem !important;
  max-height:1.8rem !important;
  padding-right:1rem;
  display: block !important;
  text-align: right;
  position:absolute !important;
  bottom:0;
  width:100%;
}
.left-panel {
  border-radius: 0 !important;
  height:100%;
}
.left-panel .panel-heading {
    border-radius: 0 !important;
}

.fullheight {
  height:101%;
}

.empty-output {
  height: 101%;
  background: #919191;
  display: flex;
  flex-wrap: nowrap;
  justify-content: center;
  align-items: center;
}
.empty-output-message {
  width: 60%;
  box-shadow: 0 0.5em 1em -0.125em rgba(10, 10, 10, 0.1), 0 0px 0 1px rgba(10, 10, 10, 0.02);
}


.fws-table {
  border: 1px solid black;
  margin-bottom: 16px;
  border-collapse: collapse;
  font-family: monospace;
  font-size: 12px;
}

.fws-table thead{
  white-space: nowrap;
  text-align: center;
  background: #f3f3f3;
  border-bottom: 2px solid black;
}

.fws-table td {
  padding-left: 8px;
  padding-right: 8px;
  padding-top:4px;
  padding-bottom: 4px;
  border-left: 1px solid black;
}

.fws-table tbody.fws-row-group tr:first-child td{
  padding-top: 8px;
}

.fws-table tbody.fws-row-group tr:last-child td{
  padding-bottom: 8px;
}

.fws-table tbody.fws-row-group {
  border-bottom: 1px solid black; 
}

.fws-table.singleline td {
  border-bottom: 1px solid black; 
}

.fws-table td span:focus {
outline: 0px solid transparent;
}

</style>
