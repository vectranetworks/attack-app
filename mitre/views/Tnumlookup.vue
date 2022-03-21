<style>
@import "css/mitre.css";
</style>

<template>
  <div>
    <h3 class="print-hidden">MITRE ATT&CK Technique Lookup</h3>
    <div class="q-pa-md">
      <div class="q-gutter-sm print-hidden" style="max-width: 300px">
        <q-input
          v-model="value1"
          filled
          @keyup.enter="store.tnumLookup($event)"
          placeholder="T1234"
          hint="Hit enter to lookup technique number"
        ></q-input>
      </div>
      <div class="row"><br /></div>
      <div class="row" v-if="store.tnumData.description">
        <template v-if="store.tnumData.description">
          <div class="col">
            <h4>
              Description of technique <b>{{ store.tnumData.name }}</b> ({{
                store.tnumData.tnum
              }}):
            </h4>
            <p>
              <!-- {{ store.tnumData.description }} -->
              <div v-html="markdown(store.tnumData.description)"></div>
            </p>
          </div>
        </template>
      </div>
      <div class="q-gutter-sm" v-if="store.tnumData.loaded">
        <q-banner class="bg-primary text-white" v-if="store.tnumData.loaded">
          Groups utilizing technique <b>{{ store.tnumData.name }}</b> ({{
            store.tnumData.tnum
          }}) in MITRE ATT&CK
        </q-banner>
      </div>
      <div class="row" v-if="store.tnumData.groups.length > 0">
        <template v-if="store.tnumData.groups">
          <table class="table">
            <tbody>
              <template v-for="group in store.tnumData.groups">
                <tr>
                  <th>
                    {{ group.name }}
                  </th>
                  <td>
                    <!-- {{ group.description }} -->
                    <div v-html="markdown(group.description)"></div>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </template>
      </div>
      <div class="q-gutter-sm">
        <q-banner class="bg-primary text-white" v-if="store.tnumData.loaded">
          Malware & Tools utilizing technique
          <b>{{ store.tnumData.name }}</b> ({{ store.tnumData.tnum }}) in MITRE
          ATT&CK
        </q-banner>
      </div>
      <div class="row">
        <template v-if="store.tnumData.software.length > 0">
          <table class="table">
            <tbody>
              <template v-for="software in store.tnumData.software">
                <tr>
                  <th>
                    {{ software.name }}
                  </th>
                  <td>
                    <!-- {{ software.description }} -->
                    <div v-html="markdown(software.description)"></div>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </template>
      </div>
      <div class="q-gutter-sm">
        <q-banner class="bg-primary text-white" v-if="store.tnumData.loaded">
          Cognito Detect detection coverage of technique
          <b>{{ store.tnumData.name }}</b> ({{ store.tnumData.tnum }}) in MITRE
          ATT&CK
        </q-banner>
      </div>
      <div class="row">
        <template v-if="store.tnumData.detections.length > 0">
          <table class="table">
            <tbody>
              <template v-for="detection in store.tnumData.detections">
                <tr>
                  <th>
                    {{ detection }}
                  </th>
                </tr>
              </template>
            </tbody>
          </table>
          <div class="q-pa-md q-gutter-sm print-hidden">
            <q-btn
              style="margin-top: 50px" 
              class="material-icons-outlined print-hidden" 
              @click="copy(store.tnumData.detections)" 
              icon="content_copy" 
            >
              <q-tooltip class="bg-accent">Copy detection list</q-tooltip>
            </q-btn>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>

<script>
import store from "store/tnumlookup.mjs";
import { ref } from "vue";
export default {
  setup() {
    return {
      store,
      value1: ref(""),
    };
  },

  methods: {
    markdown: function (input) {
      if (input) {
        // console.log(`${marked.parse(input)}`);
        return `${marked.parse(input)}`;
      } else return null;
    },

    copy(s) {
      let values = [...s];
      // console.log(values);
      navigator.clipboard.writeText(values.join(", "));
     },
    
  },

  computed: {},
};
</script>
