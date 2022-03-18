import { reactive } from "vue";
module.exports = reactive({
  softwareData: {
    error: false,
    loaded: false,
    data: {},
  },

  threatSoftwareData: {
    error: false,
    loaded: false,
    data: {},
    description: "",
  },

  selectedSoftware: null,
  softwareDescription: "",

  //Store Functions
  getSoftwareList: async function () {
    // Call an API endpoint
    try {
      let fetchData = await axios({
        method: "get",
        url: "api/software",
      });
      if (fetchData.data) {
        this.softwareData = {
          loaded: true,
          data: fetchData.data,
          error: false,
        };
      }
      // console.log(this.softwareData);
    } catch (err) {
      console.error(err);
      this.softwareData.error = true;
    }
  },

  fetchSoftware: async function (softwareName) {
    console.log(`fetchSoftware software name ${softwareName} selected`);
    // Call an API endpoint
    try {
      let fetchData = await axios({
        method: "get",
        url: `api/get_malware_tool?software=${softwareName}`,
      });
      if (fetchData.data) {
        // Retrieve description, and then delete as it should not be a key
        // console.log(fetchData.data.description);
        this.softwareDescription = fetchData.data.description;
        delete fetchData.data.description;
        // console.log(this.softwareDescription);

        // Delete name property as currently not used
        // delete fetchData.data.name;

        this.threatSoftwareData = {
          loaded: true,
          data: fetchData.data,
          description: this.softwareDescription,
          error: false,
        };
      }
      // console.log(this.threatSoftwareData);
    } catch (err) {
      console.error(err);
      this.threatSoftwareData.error = true;
    }
  },
});
