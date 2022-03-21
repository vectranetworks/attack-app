<style>
@import "css/mitre.css";
</style>

<template>
  <div>
    <h3 class="print-hidden">Threat Groups</h3>
    <div class="q-pa-md">
      <div class="q-gutter-sm print-hidden">
        <q-banner class="bg-primary text-white " v-if="store.selectedGroup">
          You have selected: <b>{{ store.selectedGroup.value }}</b> who is know
          by: <b>{{ store.selectedGroup.name }}</b> in MITRE ATT&CK
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

          <q-toggle
            v-model="showempty"
            color="red"
            label="Show Empty Values"
          />
        </div>
        <!-- <div class="showempty" @click="showempty = !showempty">
          {{ showempty ? "Hide" : "Show" }} Empty Values
        </div>
        <div
          class="showempty"
          @click="showtnumdescriptions = !showtnumdescriptions"
        >
          {{ showtnumdescriptions ? "Hide" : "Show" }} T-number descriptions
        </div>
        <div
          class="showempty"
          @click="showgroupdetections = !showgroupdetections"
        >
          {{ showgroupdetections ? "Hide" : "Show" }} Cognito Detection List
        </div> -->
      </div>
      <div class="print-show-title" v-if="store.selectedGroup"><h3>Threat Group {{ store.selectedGroup.name }}</h3></div>
      <div class="row" v-if="store.selectedGroup">
        <template v-if="store.threatGroupData.loaded">
          <template
            v-if="store.threatGroupData.loaded"
            v-for="cat in Object.keys(store.threatGroupData.data)"
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
                    v-if="
                      store.threatGroupData.data[cat][tnum].detections.length ||
                      showempty
                    "
                  >
                    <th
                      :rowspan="
                        store.threatGroupData.data[cat][tnum].detections
                          .length + 1
                      "
                    >
                      {{ tnum }}
                    </th>
                  </tr>
                  <tr
                    v-if="
                      store.threatGroupData.data[cat][tnum].detections.length ||
                      showempty
                    "
                    v-for="det in store.threatGroupData.data[cat][tnum]
                      .detections"
                  >
                    <td>
                      {{ det }}
                    </td>
                  </tr>
                </template>
              </tbody>
            </table>
          </template>
        </template>
      </div>
      <div class="row" v-if="store.selectedGroup">
        <template v-if="showtnumdescriptions">
          <table class="table">
            <thead>
              <tr>
                <th colspan="2">
                  Cognito's Coverage of MITRE Techniques, Descriptions used by
                  {{ store.selectedGroup.value }}
                </th>
              </tr>
            </thead>
            <template v-for="item in groupDescriptions">
              <tr>
                <th>
                  {{ item.tnum }}
                </th>
                <td>
                  {{ item.description }}
                </td>
              </tr>
            </template>
          </table>
        </template>
      </div>
      <template v-if="showgroupdetections && store.selectedGroup">
        <div class="row">
        </div>
        <div class="row">
          <div class="column">
          <table class="table" id="detections_table">
            <thead>
              <tr>
                <th colspan="2">
                  Cognito's Coverage of MITRE Techniques for Group
                  {{ store.selectedGroup.value }}
                </th>
              </tr>
            </thead>
            <template v-for="det in groupDetections">
              <tr>
                <th>
                  {{ det }}
                </th>
                <template v-if="showgroupdetectionsteps">
                  <td>
                    {{ det }}
                  </td>
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
      <template v-if="store.selectedGroup && store.threatGroupData.description">
        <div class="row">
          <h5>
            <b>{{ store.selectedGroup.value }}</b> description:
          </h5>
        </div>
        <div class="row">
        <p>
            <!-- {{ store.threatGroupData.description }}</p> -->
          <div v-html="markdown(store.threatGroupData.description)"></div>
          </p>
        </div>
      </template>
    </div>
  <!-- </div> -->
</template>

<script>
import store from "store/groups.mjs";
import { ref } from "vue";

export default {
  setup() {
    return {
      store,
      showempty: ref(true),
      showtnumdescriptions: ref(false),
      showgroupdetections: ref(false),
      showgroupdetectionsteps: ref(false),
      options: ref([]),
    };
  },

  methods: {
    copy(s) {
      let values = [...s];
      // console.log(values);
      navigator.clipboard.writeText(values.join(", "));
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
        console.log(groupDescriptionsData);

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
