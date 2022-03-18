import { reactive } from "vue";
module.exports = reactive({
  groupData: {
    error: false,
    loaded: false,
    data: [],
    description: "",
  },

  groupDescription: "",

  threatGroupData: {
    error: false,
    loaded: false,
    data: {},
    description: "",
  },

  selectedGroup: null,

  //Store Functions
  getGroups: async function () {
    // Call an API endpoint
    try {
      let fetchData = await axios({
        method: "get",
        url: "http://localhost:5000/api/groups",
      });
      if (fetchData.data) {
        this.groupData = {
          loaded: true,
          data: fetchData.data,
          error: false,
        };
      }
      // console.log(this.groupData);
    } catch (err) {
      console.error(err);
      this.groupData.error = true;
    }
  },

  fetchThreatGroup: async function (groupName) {
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
  },
});
