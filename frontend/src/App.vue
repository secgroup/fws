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

        <b-tab-item icon="search" label="Query" :disabled="isWorking"></b-tab-item>
        <b-tab-item icon="cog" label="Compiler" :disabled="isWorking"></b-tab-item>
      </b-tabs>
    </template>

    <template slot="end">
      <b-navbar-item tag="div">
        <div class="buttons">
          <b-button icon-left="play" type="is-primary" v-if="getCurrentMode() == 'query'" @click="queryRun" :disabled="isWorking">Run</b-button>

          <b-button icon-left="save" type="is-primary" v-if="getCurrentMode() == 'compiler'" :disabled='Object.keys(fwspolicy).length == 0' @click="compilerSave">Save</b-button>
          <b-button icon-left="folder-open" type="is-primary" v-if="getCurrentMode() == 'compiler'" @click="modaltrigger.isLoadTableActive=true">Load</b-button>

          <b-dropdown aria-role="list" v-if="getCurrentMode() == 'compiler'" :disabled='Object.keys(fwspolicy).length == 0' >
            <button class="button is-primary" slot="trigger" slot-scope="{ active }"  type="is-primary">
              <b-icon pack="fa" icon="cogs"></b-icon>
              <span>Compile</span>
              <b-icon pack="fa" :icon="active ? 'angle-up' : 'angle-down'"></b-icon>
            </button>

            <b-dropdown-item v-for="target in frontends" v-bind:key="target" aria-role="listitem" @click="compilerCompile(target)">{{ target }}</b-dropdown-item>
        </b-dropdown>


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
            <b-button icon-left="folder-open" class="button is-link is-outlined is-fullwidth" @click="modaltrigger.isLoadPolicyActive=true">
              Load Policy
            </b-button>
          </div>

          <a class="panel-block" v-for="item in loaded_policies" @click="compilerSynthesize(item)" :key="item">
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

         <div class="fullheight" style="overflow: scroll;" v-if="Object.keys(fwspolicy).length || query_progress > 0">
           <div class="mt-5 ml-5 mr-5 mb-5 pt-5 pb-5 pl-5 pr-5">

             <h1 v-if="isWorking && query_progress > 0" class="is-size-6 has-text-centered has-text-weight-bold is-family-monospace">Synthesizing policy...</h1>
             <b-progress class="mt-3 ml-3 mr-3 mb-5" :value="query_progress" show-value format="percent" v-if="isWorking && query_progress > 0"></b-progress>

             <div v-for="mode in Object.keys(fwspolicy)" v-bind:key="mode">
               <h1 class="is-size-5 has-text-weight-bold is-family-monospace">{{ mode.toUpperCase() }}</h1>

                <table class="fws-table singleline" v-if="mode == 'aliases'">
                 <thead>
                   <tr>
                     <td v-for="field in ['Name', 'Address']" v-bind:key="field"><b>{{ field }}</b></td>
                     <td>
                       <b-icon pack="fa" icon="wrench" class="has-text-grey-light"/>
                       <b-tooltip label="Add Row">
                         <span class="fa fa-plus-circle" @click="fwspolicy.aliases.push(['---', '----'])"></span>
                       </b-tooltip>
                     </td>
                   </tr>
                 </thead>

                 <tr v-for="(alias,index) in fwspolicy.aliases" v-bind:key="index">
                   <td><contenteditable :value.sync="alias[0]"/></td>
                   <td><contenteditable :value.sync="alias[1]"/></td>
                   <td style="text-align:center; vertical-align: middle; background: #f5f5f5;">
                     <b-tooltip label="Delete Row">
                       <span class="fa fa-times-circle" @click="fwspolicy.aliases.splice(index,1)"></span>
                     </b-tooltip>
                   </td>
                 </tr>
               </table>

               <table class="fws-table singleline" v-for="tab in fwspolicy[mode]" v-bind:key="tab" v-else>
                 <thead>
                   <tr>
                     <td v-for="field in tab.field_names" v-bind:key="field"><b>{{ field }}</b></td>
                     <td>
                       <b-icon pack="fa" icon="wrench" class="has-text-grey-light"/>
                       <b-tooltip label="Add Row">
                         <span class="fa fa-plus-circle" @click="tab.table.push(Object.fromEntries( tab.fields.map(x => [x, '*']) ))"></span>
                       </b-tooltip>
                     </td>
                   </tr>
                 </thead>

                 <tr v-for="(row,index) in tab.table" v-bind:key="index">
                   <td v-for="field in tab.fields" v-bind:key="field"><contenteditable :value="p2h(row[field])" @update:value="v => row[field] = h2p(v)" /></td>
                   <td style="text-align:center; vertical-align: middle; background: #f5f5f5;">
                     <b-tooltip label="Delete Row">
                       <span class="fa fa-times-circle" @click="tab.table.splice(index,1)"></span>
                     </b-tooltip>
                   </td>
                 </tr>

               </table>
             </div>

           </div>
         </div>

         <div class="empty-output" v-if="Object.keys(fwspolicy).length == 0 && query_progress == 0">
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

           <div class="fullheight" style="overflow: scroll;" ref="queryOutputContainer" v-if="query_progress || query_output">
             <div class="container">
               <pre v-html="query_output" style="background: white; overflow-x: unset;"></pre>
               <b-progress class="mt-3 ml-3 mr-3 mb-5" :value="query_progress" show-value format="percent" v-if="isWorking && query_progress > 0.1"></b-progress>
               <b-progress class="mt-3 ml-3 mr-3 mb-5" v-if="isWorking && query_progress <= 0.1"></b-progress>
             </div>
         </div>

           <div class="empty-output" v-if="!query_progress && !query_output">
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
    <span v-else> <span @click=initRepl()><b-icon pack="fa" icon="check-circle"/></span> [FWS:{{ fws_instance }}] ready </span>
  </div>

<b-modal
  v-model="modaltrigger.isLoadPolicyActive"
  has-modal-card
  trap-focus
  :destroy-on-hide="false"
  aria-role="dialog"
  aria-modal>
  <form action="">
    <div class="modal-card" style="">
      <header class="modal-card-head">
        <p class="modal-card-title">Load Policy</p>
        <button
          type="button"
          class="delete"
          @click="modaltrigger.isLoadPolicyActive=false"/>
      </header>
      <section class="modal-card-body">

        <b-field label="Name" class="has-text-centered">
            <b-input v-model="load_policy_data.name"></b-input>
        </b-field>

        <b-field label="Frontend" class="has-text-centered">
          <b-select v-model="load_policy_data.frontend" placeholder="Select a name">
            <option
              v-for="option in frontends"
              :value="option"
              :key="option">
              {{ option}}
            </option>
          </b-select>
        </b-field>

        <b-field label="Policy" class="has-text-centered">
          <b-upload  v-model="load_policy_data.policy" class="file-label">
            <span class="file-cta">
              <b-icon class="file-icon" icon="upload"></b-icon>
              <span class="file-label pr-6 pl-6">Click to upload</span>
            </span>
            <span class="file-name" v-if="load_policy_data.policy">
              {{ load_policy_data.policy.name }}
            </span>
          </b-upload>
        </b-field>

        <b-field label="Config File" class="has-text-centered">
          <b-upload  v-model="load_policy_data.config" class="file-label">
            <span class="file-cta">
              <b-icon class="file-icon" icon="upload"></b-icon>
              <span class="file-label pr-6 pl-6">Click to upload</span>
            </span>
            <span class="file-name" v-if="load_policy_data.config">
              {{ load_policy_data.config.name }}
            </span>
          </b-upload>
        </b-field>

      </section>
      <footer class="modal-card-foot">
        <button class="button" type="button" @click="modaltrigger.isLoadPolicyActive=false">Close</button>
        <button class="button is-primary" @click.prevent="loadPolicy">Load</button>
      </footer>
    </div>
  </form>
</b-modal>

<b-modal
  v-model="modaltrigger.isLoadTableActive"
  has-modal-card
  trap-focus
  :destroy-on-hide="false"
  aria-role="dialog"
  aria-modal>
  <form action="">
    <div class="modal-card" style="">
      <header class="modal-card-head">
        <p class="modal-card-title">Load Table File</p>
        <button
          type="button"
          class="delete"
          @click="modaltrigger.isLoadTableActive=false"/>
      </header>
      <section class="modal-card-body">

        <b-field label="Table File" class="has-text-centered">
          <b-upload  v-model="load_table_file" class="file-label">
            <span class="file-cta">
              <b-icon class="file-icon" icon="upload"></b-icon>
              <span class="file-label pr-6 pl-6">Click to upload</span>
            </span>
            <span class="file-name" v-if="load_table_file">
              {{ load_table_file.name }}
            </span>
          </b-upload>
        </b-field>


      </section>
      <footer class="modal-card-foot">
        <button class="button" type="button" @click="modaltrigger.isLoadTableActive=false">Close</button>
        <button class="button is-primary" @click.prevent="compilerLoad">Load</button>
      </footer>
    </div>
  </form>
</b-modal>

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
            return fetch(`${FWS_URI}/${this.fws_instance}/eval`, {
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
                let partial_bar = new RegExp('\\rSolving:.*|\\r.*', 'g')

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
                    if (this.getCurrentMode() == 'query')
                        this.$refs.queryOutputContainer.scrollTo(0, this.$refs.queryOutputContainer.children[0].offsetHeight)
                }
                this.query_output = output
                if (this.getCurrentMode() == 'query')
                    this.$refs.queryOutputContainer.scrollTo(0, this.$refs.queryOutputContainer.children[0].offsetHeight)
                this.isWorking = false;
                this.query_progress = 0;
            }).catch(e => {this.showError(e); this.isWorking = false; this.query_progress = 0;})
        },
        compilerSynthesize(policy) {
            if (this.getCurrentMode() != 'compiler') return
            this.fwspolicy = {}
            var query_code_backup = this.query_code
            this.query_code = `table_style json\naliases(${policy})\nsynthesis(${policy})\n`
            this.queryRun().then(() => {
                const sregex = /FORWARD\n\n(\{.*\})\n?(\{.*\}?)\n\nINPUT\n\n(\{.*\})(\n\{.*\})?\n\nOUTPUT\n\n(\{.*\})(\n\{.*\})?\n\nLOOPBACK\n\n(\{.*\})(\n\{.*\})?/
                const aregex = /([a-zA-Z0-9_-]+): ([0-9./]+)/g
                console.log(this.query_output)
                const match = this.query_output.match(sregex)
                if (!match)
                    this.showError(this.query_output.replaceAll("<", "&lt;"))
                else {
                    this.fwspolicy = {
                        'aliases':  [...this.query_output.matchAll(aregex)].map(x => [x[1], x[2]]),
                        'forward':  Array.prototype.concat([JSON.parse(match[1])], (match[2] ? [JSON.parse(match[2])] : [])),
                        'input':    Array.prototype.concat([JSON.parse(match[3])], (match[4] ? [JSON.parse(match[4])] : [])),
                        'output':   Array.prototype.concat([JSON.parse(match[5])], (match[6] ? [JSON.parse(match[6])] : [])),
                        'loopback': Array.prototype.concat([JSON.parse(match[7])], (match[8] ? [JSON.parse(match[8])] : []))
                    }
                }
                this.query_code = query_code_backup
                this.query_output = ''
            });
        },
        compilerSave(){
            const data = JSON.stringify(this.fwspolicy)
            const blob = new Blob([data], {type: 'text/plain'})
            const e = document.createEvent('MouseEvents'),
                  a = document.createElement('a');
            a.download = `fws_policy_${new Date().toJSON()}.json`;
            a.href = window.URL.createObjectURL(blob);
            a.dataset.downloadurl = ['text/json', a.download, a.href].join(':');
            e.initEvent('click', true, false, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);
            a.dispatchEvent(e);
        },
        async compilerLoad() {
            if (!this.load_table_file)
                this.showError("Please fill all the fields!")
            else {
                try{
                    const file_text = await this.load_table_file.text()
                    console.log(file_text)
                    this.fwspolicy = JSON.parse(file_text)
                    this.modaltrigger.isLoadTableActive = false
                } catch (e) {
                    this.showError(e)
                }
            }
        },
        compilerCompile(target){
            this.isWorking = true

            fetch(`${FWS_URI}/compiler/translate`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        'target': target,
                        'fwspolicy': JSON.stringify(this.fwspolicy)
                    })
                }).then(b => b.json())
                .then(res => {
                    console.log(res)
                    this.isWorking = false
                    // TODO
                }).catch(this.showError)

        },
        async loadPolicy() {
            const { name, frontend, policy, config } = this.load_policy_data
            if (!name || !frontend || !policy || !config)
                this.showError("Please fill all the fields!")
            else {
                const policy_text = await policy.text()
                const conf_text = await config.text()
                fetch(`${FWS_URI}/${this.fws_instance}/load_policy`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        'name': name,
                        'frontend': frontend,
                        'policy': policy_text,
                        'conf': conf_text,
                    })
                }).then(b => b.json())
                .then(res => {
                    console.log(res)
                    if (this.loaded_policies.indexOf(res['value']) < 0)
                        this.loaded_policies.push(res['value'])
                    this.modaltrigger.isLoadPolicyActive = false
                }).catch(this.showError)
            }

        },
        initRepl() {
            fetch(`${FWS_URI}/new_repl`).then(b => b.json())
                .then(res => {
                    console.log(res)
                    this.fws_instance = res['value']
                    this.isWorking = false;
                }).catch(this.showError)
            fetch(`${FWS_URI}/frontends`).then(b => b.json())
                .then(res => {
                    console.log(res)
                    this.frontends = res
                }).catch(this.showError)
        },

    },

    mounted() {
        this.initRepl()
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
            load_policy_data: { name: null, frontend: null, policy: null, config: null },
            load_table_file: null,
            loaded_policies: [],
            isWorking: true,
            frontends: [],
            fws_instance: null,
            query_code: "",
            query_output: "",
            query_progress: 0,
            fwspolicy: {},
            modaltrigger: {
                isLoadPolicyActive: false,
                isLoadTableActive: false,
            },
        };
    }
}
</script>

<style>
.components-container {
  position: relative;
  height: calc( 100vh - 3.75rem - 1.7rem );
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
  height:100%;
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
