<style>
@import "css/mitre.css";
</style>

<template>
  <div>
    <h3>Threat Groups</h3>
    <div class="q-pa-md">
      <div class="q-gutter-sm">
        <q-banner class="bg-primary text-white" v-if="store.selectedGroup">
          You have selected: <b>{{ store.selectedGroup.value }}</b> who is know
          by: <b>{{ store.selectedGroup.name }}</b> in MITRE ATT&CK
        </q-banner>
        <q-select
          filled
          v-model="store.selectedGroup"
          @update:model-value="store.fetchThreatGroup(store.selectedGroup.name)"
          :options="groups"
          label="Threat Group Alias"
        />
        <div class="showempty" @click="showempty = !showempty">
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
        </div>
      </div>

      <div class="row">
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
      <div class="row">
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
      <template v-if="showgroupdetections">
        <div class="row">
          <div
            class="showempty"
            @click="showgroupdetectionsteps = !showgroupdetectionsteps"
          >
            {{ showgroupdetectionsteps ? "Hide" : "Show" }} Detection
            Investigation Steps
          </div>
        </div>
        <div class="row">
          <table class="table">
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
      </template>
      <template v-if="store.threatGroupData.description">
        <div class="row">
          <h5>
            <b>{{ store.selectedGroup.value }}</b> description:
          </h5>
          <p>{{ store.threatGroupData.description }}</p>
        </div>
      </template>
    </div>
  </div>
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
    };
  },

  methods: {
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

    /* computedColumns: function () {
      let columns = [];
      const columnNames = Object.keys(store.threatGroupData.data);

      columns.push({
        name: "name",
        label: "Techniques",
        field: (row) => row.name,
        format: (val) => `${val}`,
        align: "center",
        sortable: true,
      });

      for (let colname of columnNames) {
        columns.push({
          name: colname,
          label: colname,
          field: colname,
          align: "center",
          sortable: true,
        });
      }
      console.log(columns);
      return columns;
    }, */

    /* columnNames: function () {
      let names = new Set();
      names = Object.keys(store.threatGroupData.data);

      return names;
    }, */

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
      return items;
    },
  },

  mounted: function () {
    store.getGroups();
  },
};
</script>
