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
        <template class="q-pa-md" v-if="store.tnumData.loaded">
          <br />
        </template>
        <q-btn
          icon="print"
          class="print-hidden"
          @click="printDoc()"
          label="Print Results"
          v-if="store.tnumData.loaded"
          color="green"
        ></q-btn>
      </div>
    </div>
    <div id="printArea" class="q-pa-md">
      <div class="row">
        <br />
        <div class="row" v-if="store.tnumData.name">
          <div class="print-show-title">
            <h1 class="sectionTitle">
              MITRE Technique {{ store.tnumData.name }}
            </h1>
          </div>
        </div>
        <div class="row" v-if="store.tnumData.description">
          <template v-if="store.tnumData.description">
            <div class="row">
              <h3 class="sectionTitle">
                Description of technique
                <u>
                  {{ store.tnumData.name }}
                </u>
                ({{ store.tnumData.tnum }}):
              </h3>
              <div class="row">
                <div v-html="markdown(store.tnumData.description)"></div>
              </div>
            </div>
          </template>
        </div>
        <div class="row" v-if="store.tnumData.phase">
          <template v-if="store.tnumData.phase">
            <div class="row">
              <h3 class="sectionTitle">
                MITRE Phase:
                <u>
                  {{ toTitleCase(store.tnumData.phase) }}
                </u>
              </h3>
            </div>
          </template>
        </div>
      </div>
      <!-- Groups using technique -->
      <div class="q-gutter-sm print-hidden" v-if="store.tnumData.loaded">
        <q-banner class="bg-primary text-white" v-if="store.tnumData.loaded">
          Groups utilizing technique <b>{{ store.tnumData.name }}</b> ({{
            store.tnumData.tnum
          }}) in MITRE ATT&CK
        </q-banner>
        <br />
      </div>
      <div class="row" v-if="store.tnumData.groups.length > 0">
        <template v-if="store.tnumData.groups">
          <!-- <div class="pageBreak" /> -->
          <div class="print-show-title">
            <h3 class="sectionTitle">Groups Utilizing Technique</h3>
            This section describes the groups known to utilize the MITRE
            Technique {{ store.tnumData.name }}.
            <br />
            <br />
          </div>
          <table class="table">
            <thead>
              <tr>
                <th class="titleWidth">Group</th>
                <th>Description</th>
              </tr>
            </thead>
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
      <!-- Malware & Tools Utilizing Technique -->
      <div class="q-gutter-sm">
        <q-banner
          class="bg-primary text-white print-hidden"
          v-if="store.tnumData.loaded"
        >
          Malware & Tools utilizing technique
          <b>{{ store.tnumData.name }}</b> ({{ store.tnumData.tnum }}) in MITRE
          ATT&CK
        </q-banner>
        <br />
      </div>
      <div class="row">
        <template v-if="store.tnumData.software.length > 0">
          <!-- <div class="pageBreak" /> -->
          <div class="print-show-title">
            <h3 class="sectionTitle">Malware & Tools Utilizing Technique</h3>
            This section describes the Malware & Tools known to utilize the
            MITRE Technique {{ store.tnumData.name }}.
            <br />
            <br />
          </div>
          <table class="table">
            <thead>
              <tr>
                <th class="titleWidth">Name</th>
                <th>Description</th>
              </tr>
            </thead>
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
      <!-- Cognito detections -->
      <template v-if="store.tnumData.detections.length > 0">
        <div class="q-gutter-sm">
          <q-banner
            class="bg-primary text-white print-hidden"
            v-if="store.tnumData.loaded"
          >
            Cognito Detect detection coverage of technique
            <b>{{ store.tnumData.name }}</b> ({{ store.tnumData.tnum }}) in
            MITRE ATT&CK
          </q-banner>
          <br />
        </div>
        <div class="pageBreak" />
        <div class="print-show-title">
          <h3 class="sectionTitle">
            Cognito's Coverage of MITRE Technique
            {{ store.tnumData.tnum }}
          </h3>
          This section describes the detections within Cognito Detect that are
          known to trigger on the technique <b>{{ store.tnumData.name }}</b> (
          {{ store.tnumData.tnum }}).
          <br />
          <br />
        </div>
        <div class="row">
          <div class="column">
            <template v-if="store.tnumData.detections.length > 0">
              <table class="table techniques" id="detections_table">
                <thead>
                  <tr>
                    <th class="detTitleWidth">Detection</th>
                  </tr>
                </thead>
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
            </template>
          </div>
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
        </div>
      </template>
    </div>
  </div>
</template>

<script>
import store from "store/tnumlookup.mjs";
import { ref } from "vue";
import { Print } from "../mixins/print.mjs";

export default {
  setup() {
    return {
      store,
      value1: ref(""),
    };
  },

  mixins: [Print],

  methods: {
    printDoc: function () {
      let content = document.getElementById("printArea").innerHTML;
      this.printDocument(content, this.store.tnumData.name);
    },

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

    title(str) {
      return str.replace(/(^|\s)\S/g, function (t) {
        return t.toUpperCase();
      });
    },

    toTitleCase: function (t) {
      let newStr = t
        .split("-")
        .map((w) => w[0].toUpperCase() + w.substring(1).toLowerCase())
        .join(" ");
      return newStr;
    },
  },

  computed: {},
};
</script>
