<template>
  <span
    contenteditable="true"
    @input="update"
    @focus="focus"
    @blur="blur"
    v-html="valueText"
    @keyup.ctrl.delete="deleterow"
  ></span>
</template>

<script>
export default {
    name: 'contenteditable',
    props: {
        value: {
            type: String,
            default: ''
        },
    },
    data() {
        return {
            focusIn: false,
            valueText: ''
        }
    },
    computed: {
        localValue: {
            get: function() {
                return this.value
            },
            set: function(newValue) {
                this.$emit('update:value', newValue)
            }
        }
    },
    watch: {
        localValue(newVal) {
            if (!this.focusIn) {
                this.valueText = newVal
            }
        }
    },
    created() {
        this.valueText = this.value 
    },
    methods: {
        deleterow(){
            this.$emit('delete-row');  
        },
        update(e) {
      this.localValue = e.target.innerHTML
    },
    focus() {
      this.focusIn = true
    },
    blur() {
      this.focusIn = false
    }
  }
} 
</script>

<style></style>
