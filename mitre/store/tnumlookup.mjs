import { reactive } from "vue";
module.exports = reactive({
  tnumData: {
    error: false,
    loaded: false,
    detections: [],
    groups: [],
    software: [],
    description: "",
    name: "",
    tnum: "",
  },

  tnumDescription: "",

  //Store Functions
  tnumLookup: async function (event) {
    console.log(event.srcElement.value);
    try {
      let fetchData = await axios({
        method: "get",
        url: `http://localhost:5000/api/get_tnum_info?tnum=${event.srcElement.value}`,
      });
      if (!fetchData.data.error) {
        this.tnumData = {
          loaded: true,
          detections: fetchData.data.detections,
          groups: fetchData.data.groups,
          software: fetchData.data.software,
          description: fetchData.data.description,
          name: fetchData.data.name,
          tnum: fetchData.data.tnum,
          error: false,
        };
      } else {
        this.tnumData = {
          error: true,
          loaded: false,
          description: "",
          detections: [],
          groups: [],
          software: [],
          name: "",
          tnumn: "",
        };
      }
      // console.log(this.groupData);
    } catch (err) {
      console.error(err);
      this.tnumData.error = true;
      this.tnumData.loaded = false;
      this.tnumData.description = "";
    }
  },

  /* fetchThreatGroup: async function (groupName) {
    console.log(`fetchThreatGroup group ${groupName} selected`);
    // Call an API endpoint
    try {
      let fetchData = await axios({
        method: "get",
        url: `http://localhost:5000/api/get_group?group=${groupName}`,
      });
      if (fetchData.data) {
        // Retrieve description, and then delete as it should not be a key
        this.groupDescription = fetchData.data.description;
        delete fetchData.data.description;

        // Delete name property as currently not used
        delete fetchData.data.name;

        this.threatGroupData = {
          loaded: true,
          data: fetchData.data,
          description: this.groupDescription,
          error: false,
        };
        // console.log(this.threatGroupData.description);
      }
      // console.log(this.threatGroupData);
    } catch (err) {
      console.error(err);
      this.threatGroupData.error = true;
    }
  }, */
});
