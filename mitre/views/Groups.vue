<style>
@import "css/mitre.css";
</style>

<template>
  <div>
    <h3 class="print-hidden">Threat Groups</h3>
    <div class="q-pa-md">
      <div class="q-gutter-sm print-hidden">
        <q-banner class="bg-primary text-white" v-if="store.selectedGroup">
          You have selected:
          <b>{{ store.selectedGroup.value }}</b> who is known by:
          <b>{{ store.selectedGroup.name }}</b> in MITRE ATT&CK
        </q-banner>
        <q-select
          filled
          use-input
          clearable
          input-debounce="0"
          v-model="store.selectedGroup"
          @update:model-value="store.fetchThreatGroup(store.selectedGroup)"
          :options="options"
          @filter="filterFn"
          label="Threat Group Alias"
        />
      </div>
      <div class="q-pa-sm q-gutter-md print-hidden">
        <q-toggle
          v-model="showtnumdescriptions"
          color="blue"
          label="Show T-num Descriptions"
        />
        <q-toggle
          v-model="showgroupdetections"
          color="blue"
          label="Show Detections"
        />
        <q-toggle v-model="showempty" color="red" label="Show Empty Values" />
        <q-btn
          icon="print"
          class="print-hidden"
          @click="printDoc()"
          label="Print Results"
          v-if="store.selectedGroup"
          color="green"
        ></q-btn>
      </div>
      <div v-if="displaycat" class="q-gutter-md print-hidden">
        <template v-if="displaycat" v-for="cat in Object.keys(this.displaycat)">
          <q-chip
            clickable
            size="md"
            square
            dense
            @click="displaycat[cat] = !displaycat[cat]"
            :color="displaycat[cat] ? 'green' : 'red'"
            text-color="white"
          >
            {{ cat }}
          </q-chip>
        </template>
      </div>
    </div>
    <div id="printArea" class="q-pa-md">
      <div class="row" v-if="store.selectedGroup">
        <template v-if="store.threatGroupData.loaded">
          <div class="print-show-title">
            <h1 class="sectionTitle">
              Threat Group {{ store.selectedGroup.name }}
            </h1>
            <!-- <h3 class="sectionTitle">MITRE ATT&amp;CK T-Numbers</h3>
            This section will list all the T-Numbers known to be used by the
            group {{ store.selectedGroup.name }} and associated detections
            within Vectra Cognito Detect that will monitor for activity seen to
            be utilising the method. -->
            <br />
            <br />
          </div>
          <!-- Group description -->
          <template
            v-if="store.selectedGroup && store.threatGroupData.description"
          >
            <!-- <div class="pageBreak" /> -->
            <div class="row">
              <h3 class="sectionTitle">
                {{ store.selectedGroup.value }} Description
              </h3>
            </div>
            <div class="row">
              <div v-html="markdown(store.threatGroupData.description)"></div>
            </div>
          </template>
          <div class="print-show-title">
            <h3 class="sectionTitle">MITRE ATT&amp;CK T-Numbers</h3>
            This section will list all the T-Numbers known to be used by the
            group {{ store.selectedGroup.name }} and associated detections
            within Vectra Cognito Detect that will monitor for activity seen to
            be utilising the method.
            <br />
            <br />
          </div>
          <template
            v-if="store.threatGroupData.loaded"
            v-for="cat in Object.keys(store.threatGroupData.data)"
          >
            <div
              v-if="
                this.displaycat[cat] &&
                (this.showempty || detectionsCatNotEmpty([cat]))
              "
              class="col col-xl-3 col-lg-4 col-md-6 col-sm-12 col-xs-12"
            >
              <table class="table">
                <thead>
                  <tr>
                    <th colspan="2">{{ cat }}</th>
                  </tr>
                </thead>
                <tbody>
                  <template
                    v-for="tnum in Object.keys(store.threatGroupData.data[cat])"
                  >
                    <tr
                      v-for="(det, index) in store.threatGroupData.data[cat][
                        tnum
                      ].detections"
                    >
                      <th
                        :rowspan="
                          store.threatGroupData.data[cat][tnum].detections
                            .length
                        "
                        class="titleWidth"
                        v-if="index == 0"
                      >
                        {{ tnum }}
                      </th>
                      <td>{{ det }}</td>
                    </tr>
                    <tr
                      v-if="
                        !store.threatGroupData.data[cat][tnum].detections
                          .length && showempty
                      "
                    >
                      <th>{{ tnum }}</th>
                      <td></td>
                    </tr>
                  </template>
                </tbody>
              </table>
            </div>
          </template>
        </template>
      </div>
      <div class="row" v-if="store.selectedGroup">
        <template v-if="showtnumdescriptions">
          <div class="pageBreak" />
          <div class="print-show-title">
            <h3 class="sectionTitle">MITRE ATT&amp;CK T-Number Descriptions</h3>
            This section describes the MITRE Techniques known to be used by the
            group {{ store.selectedGroup.name }}.
            <br />
            <br />
          </div>
          <table class="table techniques">
            <thead>
              <tr>
                <th class="titleWidth">T-Number</th>
                <th>Description</th>
              </tr>
            </thead>
            <template v-for="item in groupDescriptions">
              <tr>
                <th class="titleWidth">{{ item.tnum }}</th>
                <td>{{ item.description }}</td>
              </tr>
            </template>
          </table>
        </template>
      </div>
      <template v-if="showgroupdetections && store.selectedGroup">
        <div class="pageBreak" />
        <div class="print-show-title">
          <h3 class="sectionTitle">
            Cognito's Coverage of MITRE Techniques for Group
            {{ store.selectedGroup.name }}
          </h3>
          This section describes the detections within Cognito Detect that are
          known to trigger on techniques used by the group
          {{ store.selectedGroup.name }}.
          <br />
          <br />
        </div>
        <div class="row">
          <div class="column">
            <table class="table techniques" id="detections_table">
              <thead>
                <tr>
                  <th class="detTitleWidth">Detections</th>
                </tr>
              </thead>
              <template v-for="det in groupDetections">
                <tr>
                  <th class="titleWidth">{{ det }}</th>
                  <template v-if="showgroupdetectionsteps">
                    <td>{{ det }}</td>
                  </template>
                </tr>
              </template>
            </table>
          </div>
          <div class="q-pa-md q-gutter-sm print-hidden">
            <q-btn
              style="margin-top: 50px"
              class="material-icons-outlined print-hidden"
              @click="copy(groupDetections)"
              icon="content_copy"
            >
              <q-tooltip class="bg-accent">Copy detection list</q-tooltip>
            </q-btn>
          </div>
        </div>
      </template>
      <!-- <template v-if="store.selectedGroup && store.threatGroupData.description">
        <div class="pageBreak" />
        <div class="row">
          <h4 class="sectionTitle">
            {{ store.selectedGroup.value }} Description
          </h4>
        </div>
        <div class="row">
          <div v-html="markdown(store.threatGroupData.description)"></div>
        </div>
      </template> -->
    </div>
  </div>
</template>

<script>
import store from "store/groups.mjs";
import { ref, reactive } from "vue";
import { Print } from "../mixins/print.mjs";

export default {
  setup() {
    return {
      store,
      showempty: ref(true),
      showtnumdescriptions: ref(true),
      showgroupdetections: ref(true),
      showgroupdetectionsteps: ref(false),
      options: ref([]),
      displaycat: reactive({}),
    };
  },

  watch: {
    categories: function () {
      console.log("calling genCategories");
      for (let cat of Object.keys(store.threatGroupData.data)) {
        this.displaycat[cat] = true;
      }
      console.log(this.displaycat);
    },
  },

  mixins: [Print],

  methods: {
    copy(s) {
      let values = [...s];
      // console.log(values);
      navigator.clipboard.writeText(values.join(", "));
    },

    printDoc: function () {
      let content = document.getElementById("printArea").innerHTML;
      this.printDocument(content, this.store.selectedGroup.name);
    },

    detectionsCatNotEmpty: function (category) {
      let detCount = 0;
      for (let tnum of Object.keys(store.threatGroupData.data[category])) {
        detCount +=
          store.threatGroupData.data[category][tnum].detections.length;
      }
      console.log(Boolean(detCount));
      return Boolean(detCount);
    },

    filterFn: function (val, update) {
      if (val === "") {
        update(() => {
          this.options = this.groups;

          // here you have access to "ref" which
          // is the Vue reference of the QSelect
        });
        return;
      }

      update(() => {
        const needle = val.toLowerCase();
        this.options = this.groups.filter(
          (v) => v.label.toLowerCase().indexOf(needle) > -1
        );
      });
    },

    getDetections: function (obj) {
      // console.log('getDetections:' + obj.detections)
      return obj.detections;
    },

    detCount: function (obj) {
      // console.log("detCount:" + obj);
      if (obj.detections.length >= 1) {
        return obj.detections.length;
      }
      return 1;
    },

    tkeys: function (obj) {
      return Object.keys(obj);
    },

    markdown: function (input) {
      if (input) {
        // console.log(`${marked.parse(input)}`);
        return `${marked.parse(input)}`;
      } else return null;
    },
  },

  computed: {
    categories: function () {
      if (store.threatGroupData.data) {
        console.log(store.threatGroupData);
        return Object.keys(store.threatGroupData.data);
      }
    },

    groupDescriptions: function () {
      let groupDescriptionsData = [];
      if (store.threatGroupData.loaded) {
        for (let cat of Object.keys(store.threatGroupData.data)) {
          for (let tnum of Object.keys(store.threatGroupData.data[cat])) {
            if (store.threatGroupData.data[cat][tnum].description) {
              groupDescriptionsData.push({
                tnum: tnum,
                description: store.threatGroupData.data[cat][tnum].description,
              });
            }
          }
        }
        // console.log(groupDescriptionsData);

        //Sort numerically
        groupDescriptionsData.sort((a, b) => (a.tnum < b.tnum ? -1 : 1));

        return groupDescriptionsData;
      } else {
        return groupDescriptionsData;
      }
    },

    groupDetections: function () {
      const groupDetectionData = new Set();
      if (store.threatGroupData.loaded) {
        for (let cat of Object.keys(store.threatGroupData.data)) {
          for (let tnum of Object.keys(store.threatGroupData.data[cat])) {
            if (store.threatGroupData.data[cat][tnum].detections) {
              store.threatGroupData.data[cat][tnum].detections.forEach(
                (element) => groupDetectionData.add(element)
              );
            }
          }
        }
        // console.log(groupDescriptionsData);
        return groupDetectionData;
      } else {
        return groupDetectionData;
      }
    },

    groups: function () {
      let items = [];
      if (store.groupData.loaded) {
        for (let item of store.groupData.data) {
          if (item.aliases) {
            // console.log("Loaded items.aliases");
            for (let alias of item.aliases) {
              if (alias) {
                items.push({
                  label: alias,
                  value: alias,
                  name: item.name,
                });
              }
            }
          }
        }
      }
      //Sort items alphabetically
      items.sort((a, b) => (a.label < b.label ? -1 : 1));
      return items;
    },
  },

  mounted: function () {
    store.getGroups();
  },
};
</script>
