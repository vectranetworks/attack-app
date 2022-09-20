<style>
@import "css/mitre.css";
</style>

<template>
  <div>
    <h3 class="print-hidden">MITRE Number Extraction</h3>
    <div class="q-pa-md">
      <div class="q-gutter-sm print-hidden">
        <q-banner class="bg-primary text-white" v-if="this.tnumList">
          Following MITRE Numbers extracted:
          {{ this.tnumList.join(", ").replace('"', "") }}
        </q-banner>
      </div>
      <div>
        <h5 class="print-hidden">
          Paste your text containing MITRE T-numbers into the box below.
        </h5>
      </div>
      <div class="q-pa-md" style="max-width: 800px">
        <q-input
          v-model="store.inputText"
          filled
          debounce="500"
          placeholder="paste your text here"
          type="textarea"
        >
        </q-input>
      </div>
      <!-- Render toggles -->
      <div v-if="store.tnumData.loaded" class="q-gutter-md print-hidden"></div>
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
      <!-- Render category selection buttons -->
      <div v-if="displaycat" class="q-gutter-md print-hidden">
        <template v-if="displaycat">
          <q-chip
            v-for="cat in Object.keys(this.displaycat)"
            :key="cat"
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

      <!-- Display T-number category and detection tables -->
      <div id="printArea" class="q-pa-md">
        <div class="row">
          <template v-if="tnumCategory">
            <div v-for="cat of Object.keys(tnumCategory)" :key="cat">
              <div
                v-if="
                  this.displaycat[cat] &&
                  (this.showempty || detectionsCatNotEmpty(cat))
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
                    <template v-for="tnum in Object.keys(tnumCategory[cat])">
                      <tr
                        v-for="(det, index) in tnumCategory[cat][tnum]
                          .detections"
                        :key="det"
                      >
                        <th
                          :rowspan="tnumCategory[cat][tnum].detections.length"
                          class="titleWidth"
                          v-if="index == 0"
                        >
                          {{ tnum }}
                        </th>
                        <td>{{ det }}</td>
                      </tr>
                      <tr
                        v-if="
                          !tnumCategory[cat][tnum].detections.length &&
                          showempty
                        "
                        :key="tnum"
                      >
                        <th>{{ tnum }}</th>
                        <td></td>
                      </tr>
                    </template>
                  </tbody>
                </table>
              </div>
            </div>
          </template>
        </div>
      </div>

      <!-- Display T-number descriptions -->
      <div class="row" v-if="store.tnumData.loaded">
        <template v-if="showtnumdescriptions">
          <div class="pageBreak" />
          <div class="print-show-title">
            <h3 class="sectionTitle">MITRE ATT&amp;CK T-Number Descriptions</h3>
            This section describes the MITRE Techniques known to be used by the
            group.
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
            <template v-for="item in store.tnumData.results">
              <tr>
                <th class="titleWidth">{{ item.tnum }}</th>
                <td><div v-html="markdown(item.description)"></div></td>
              </tr>
            </template>
          </table>
        </template>
      </div>
      <!-- Display Detections -->
    </div>
  </div>
</template>

<script>
import store from "store/extract.mjs";
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
      displaycat: ref({}),
    };
  },

  watch: {
    tnumCategory: function () {
      let items = {};
      for (let cat of Object.keys(this.tnumCategory)) {
        items[cat] = true;
      }
      this.displaycat = items;
      console.log(`displaycat: ${JSON.stringify(this.displaycat)}`);
    },

    // inputText: function () {
    //   if (store.inputText) {
    //     console.log("triggered inputText watcher");
    //     this.tnumList();
    //   }
    // },
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
      console.log("detectionCatNotEmpty returning true");
      return true;
      // let detCount = 0;
      // for (let tnum of Object.keys(tnumCategory[category])) {
      //   detCount += tnumCategory[category][tnum].detections.length;
      // }
      // console.log(Boolean(detCount));
      // return Boolean(detCount);
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
    tnumList: function () {
      if (store.inputText) {
        let tlist = store.inputText.match(/T[0-9]{4}\.[0-9]{3}|T[0-9]{4}/gi);
        if (JSON.stringify(store.tnumList2) !== JSON.stringify(tlist)) {
          store.getTnumData(tlist);
          store.tnumList2 = tlist;
        }
        return tlist;
      }
    },

    categories: function () {
      if (store.threatGroupData.data) {
        return Object.keys(store.threatGroupData.data);
      }
    },

    tnumCategory: function () {
      let tnumCategoryData = {};
      if (store.tnumData.loaded) {
        console.log("tnumCategory store.tnumData.loaded");
        for (let t of store.tnumData.results) {
          // Check to see if category key exists
          if (tnumCategoryData.hasOwnProperty(t.phase)) {
            if (t.description) {
              tnumCategoryData[t.phase] = {
                [t.tnum]: {
                  description: t.description,
                  detections: t.detections,
                },
              };
            } else {
              tnumCategoryData[t.phase] = {
                [t.tnum]: { detections: t.detections },
              };
            }
          } else if (t.description) {
            //tnumCategoryData does not already have phase
            tnumCategoryData[t.phase] = {
              [t.tnum]: {
                description: t.description,
                detections: t.detections,
              },
            };
          } else {
            tnumCategoryData[t.phase] = {
              [t.tnum]: { detections: t.detections },
            };
          }
        }

        // console.log(groupDescriptionsData);
        //Sort numerically
        // tnumCategoryData.sort((a, b) => (a.tnum < b.tnum ? -1 : 1));
        // console.log(JSON.stringify(tnumCategoryData));
        return tnumCategoryData;
      } else {
        // console.log(JSON.stringify(tnumCategoryData));
        return tnumCategoryData;
      }
    },

    extractDetections: function () {
      const DetectionData = new Set();
      if (store.threatGroupData.loaded) {
        for (let cat of Object.keys(store.threatGroupData.data)) {
          for (let tnum of Object.keys(store.threatGroupData.data[cat])) {
            if (store.threatGroupData.data[cat][tnum].detections) {
              store.threatGroupData.data[cat][tnum].detections.forEach(
                (element) => DetectionData.add(element)
              );
            }
          }
        }
        // console.log(groupDescriptionsData);
        return DetectionData;
      } else {
        return DetectionData;
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
    // store.getGroups();
  },
};
</script>
