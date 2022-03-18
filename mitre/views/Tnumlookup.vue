<style>
@import "css/mitre.css";
</style>

<template>
  <div>
    <h3>MITRE ATT&CK Technique Lookup</h3>
    <div class="q-pa-md">
      <div class="q-gutter-sm" style="max-width: 300px">
        <q-input
          v-model="value1"
          filled
          @keyup.enter="store.tnumLookup($event)"
          placeholder="T1234"
          hint="Hit enter to lookup technique number"
        ></q-input>
      </div>
      <div class="row"><br /></div>
      <div class="row">
        <template v-if="store.tnumData.description">
          <div class="col">
            Description of technique <b>{{ store.tnumData.name }}</b> ({{
              store.tnumData.tnum
            }}):
            <p>{{ store.tnumData.description }}</p>
          </div>
        </template>
      </div>
      <div class="q-gutter-sm">
        <q-banner class="bg-primary text-white" v-if="store.tnumData.loaded">
          Groups utilizing technique <b>{{ store.tnumData.name }}</b> ({{
            store.tnumData.tnum
          }}) in MITRE ATT&CK
        </q-banner>
      </div>
      <div class="row">
        <template v-if="store.tnumData.groups">
          <table class="table">
            <tbody>
              <template v-for="group in store.tnumData.groups">
                <tr>
                  <th>
                    {{ group.name }}
                  </th>
                  <td>
                    {{ group.description }}
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
        <template v-if="store.tnumData.software">
          <table class="table">
            <tbody>
              <template v-for="software in store.tnumData.software">
                <tr>
                  <th>
                    {{ software.name }}
                  </th>
                  <td>
                    {{ software.description }}
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
        <template v-if="store.tnumData.detections">
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
      // showempty: ref(true),
      // showtnumdescriptions: ref(false),
      // showgroupdetections: ref(false),
      // showgroupdetectionsteps: ref(false),
    };
  },

  methods: {
    /* getDetections: function (obj) {
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
    }, */
  },

  computed: {
    /*  groupDescriptions: function () {
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
    }, */
    /*  groupDetections: function () {
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
    }, */
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
    /* groups: function () {
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
    }, */
  },

  /*   mounted: function () {
    store.getGroups();
  }, */
};
</script>
