import { reactive } from "vue";
module.exports = reactive({
  inputText: "",
  tnumList: [],
  tnumList2: [],
  groupData: {
    error: false,
    loaded: false,
    data: [],
    description: "",
  },
  tnumData: {
    error: false,
    loaded: false,
    results: [],
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
  getTnumData: async function (tlist) {
    console.log(tlist);
    let tlistParam = "";
    let first = true;
    for (let t of tlist) {
      if (first) {
        // first parameter
        first = false;
        console.log(`tlistParam = ?tnum=${t}`);
        tlistParam = `?tnum=${t}`;
      } else {
        tlistParam = tlistParam + `&tnum=${t}`;
      }
    }
    try {
      console.log(`fetching parameter ${tlistParam}`);
      let fetchData = await axios({
        method: "get",
        url: `api/get_tnum_list_info${tlistParam}`,
      });
      if (!fetchData.data.error) {
        this.tnumData = {
          loaded: true,
          results: fetchData.data.results,
          error: false,
        };
      } else {
        this.tnumData = {
          error: true,
          loaded: false,
          results: [],
        };
      }
      // console.log(this.groupData);
    } catch (err) {
      console.error(err);
      this.tnumData.error = true;
      this.tnumData.loaded = false;
      this.tnumData.results = [];
    }
  },

  getGroups: async function () {
    // Call an API endpoint
    try {
      let fetchData = await axios({
        method: "get",
        url: "api/groups",
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

  fetchThreatGroup: async function (group) {
    if (group) {
      console.log(`fetchThreatGroup group ${group.name} selected`);
      // Call an API endpoint
      try {
        let fetchData = await axios({
          method: "get",
          url: `api/get_group?group=${group.name}`,
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
    }
  },
});
