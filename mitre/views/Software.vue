<style>
@import "css/mitre.css";
</style>

<template>
  <div>
    <h3>Malware & Tools</h3>
    <div class="q-pa-md">
      <div class="q-gutter-md">
        <q-banner class="bg-primary text-white" v-if="store.selectedSoftware">
          You have selected: <b>{{ store.selectedSoftware.value }}</b> who is
          know by: <b>{{ store.selectedSoftware.name }}</b> in MITRE ATT&CK
        </q-banner>
        <q-select filled use-input clearable input-debounce="0" v-model="store.selectedSoftware"
          @update:model-value="store.fetchSoftware(store.selectedSoftware.name)" :options="options" @filter="filterFn"
          label="Malware or Tool Alias" />

        <div class="q-pa-sm q-gutter-md print-hidden">
          <q-toggle v-model="showtnumdescriptions" color="blue" label="Show T-num Descriptions" />
          <q-toggle v-model="showgroupdetections" color="blue" label="Show Detections" />
          <q-toggle v-model="showempty" color="red" label="Show Empty Values" />
        </div>

      </div>
      <div class="row">
        <template v-if="store.selectedSoftware">
          <template v-if="store.threatSoftwareData.loaded" v-for="cat in Object.keys(store.threatSoftwareData.data)">
            <div class="col col-xl-3 col-lg-4 col-md-6 col-sm-12 col-xs-12">
              <table class="table">
                <thead>
                  <tr>
                    <th colspan="2">{{ cat }}</th>
                  </tr>
                </thead>
                <tbody>
                  <template v-for="tnum in Object.keys(store.threatSoftwareData.data[cat])">
                    <tr v-for="(det, index) in store.threatSoftwareData.data[cat][tnum].detections">
                      <th :rowspan="store.threatSoftwareData.data[cat][tnum].detections.length" class="titleWidth"
                        v-if="index == 0">{{ tnum }}</th>
                      <td>{{ det }}</td>
                    </tr>
                    <tr v-if="!store.threatSoftwareData.data[cat][tnum].detections.length && showempty">
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
      <div class="row" v-if="store.selectedSoftware">
        <template v-if="showtnumdsc">
          <table class="table">
            <thead>
              <tr>
                <th colspan="2">MITRE Technique Descriptions</th>
              </tr>
            </thead>
            <template v-for="item in softwareDescriptions">
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
      <template v-if="showsoftwaredetections && store.selectedSoftware">
        <div class="row">
          <!-- <div
            class="showempty"
            @click="showsoftwaredetectionsteps = !showsoftwaredetectionsteps"
          >
            {{ showsoftwaredetectionsteps ? "Hide" : "Show" }} Detection
            Investigation Steps
          </div> -->
        </div>
        <div class="row">
          <table class="table">
            <thead>
              <tr>
                <th colspan="2">
                  Cognito's Coverage of MITRE Techniques for
                  {{ store.selectedSoftware.name }}
                </th>
              </tr>
            </thead>
            <template v-for="det in softwareDetections">
              <tr>
                <th>
                  {{ det }}
                </th>
                <template v-if="showsoftwaredetectionsteps">
                  <td>
                    {{ det }}
                  </td>
                </template>
              </tr>
            </template>
          </table>
        </div>
      </template>
      <template v-if="store.selectedSoftware && store.threatSoftwareData.description">
        <div class="row">
          <h5>
            <b>{{ store.selectedSoftware.name }}</b> description:
          </h5>
        </div>
        <div class="row">
          <p>
            <!-- {{ store.threatSoftwareData.description }} -->
          <div v-html="markdown(store.threatSoftwareData.description)"></div>
          </p>
        </div>
      </template>
    </div>
  </div>
</template>

<script>
import store from "store/software.mjs";
import { ref } from "vue";
export default {
  setup () {
    return {
      store,
      showempty: ref(true),
      showtnumdsc: ref(false),
      showsoftwaredetections: ref(false),
      options: ref([]),
    };
  },

  methods: {
    filterFn: function (val, update) {
      if (val === "") {
        update(() => {
          this.options = this.software;

          // here you have access to "ref" which
          // is the Vue reference of the QSelect
        });
        return;
      }

      update(() => {
        const needle = val.toLowerCase();
        this.options = this.software.filter(
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
        console.log(`${marked.parse(input)}`);
        return `${marked.parse(input)}`;
      } else return null;
    },
  },

  computed: {
    softwareDescriptions: function () {
      let softwareDescriptionsData = [];
      if (store.threatSoftwareData.loaded) {
        for (let cat of Object.keys(store.threatSoftwareData.data)) {
          for (let tnum of Object.keys(store.threatSoftwareData.data[cat])) {
            if (store.threatSoftwareData.data[cat][tnum].description) {
              softwareDescriptionsData.push({
                tnum: tnum,
                description:
                  store.threatSoftwareData.data[cat][tnum].description,
              });
            }
          }
        }
        // console.log(softwareDescriptionsData);
        return softwareDescriptionsData;
      } else {
        return softwareDescriptionsData;
      }
    },

    softwareDetections: function () {
      const softwareDetectionData = new Set();
      if (store.threatSoftwareData.loaded) {
        for (let cat of Object.keys(store.threatSoftwareData.data)) {
          for (let tnum of Object.keys(store.threatSoftwareData.data[cat])) {
            if (store.threatSoftwareData.data[cat][tnum].detections) {
              store.threatSoftwareData.data[cat][tnum].detections.forEach(
                (element) => softwareDetectionData.add(element)
              );
            }
          }
        }
        // console.log(softwareDescriptionsData);
        return softwareDetectionData;
      } else {
        return softwareDetectionData;
      }
    },

    columnNames: function () {
      let names = new Set();
      names = Object.keys(store.threatSoftwareData.data);

      return names;
    },

    software: function () {
      let items = [];
      if (store.softwareData.loaded) {
        for (let item of store.softwareData.data) {
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
    store.getSoftwareList();
  },
};
</script>
