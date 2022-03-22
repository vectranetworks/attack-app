const newLogo =
  "data:image/png;base64,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";

export const Print = {
  setup() {
    return {};
  },
  components: {},
  methods: {
    printDocument: function (content, title) {
      var left = screen.width / 2 - 930 / 2;
      var top = screen.height / 2 - 690 / 2;
      var mywindow = window.open(
        "",
        "VSK Report",
        "toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=no, resizable=no, copyhistory=no, width=930, height=690, top=" +
          top +
          ", left=" +
          left
      );

      let document = `
      <html>
        <head>
          <title>Threat Group${title}</title>
          <style>
            @media print {
              .titleLogo {
                width: 100%;
                position: absolute;
                left: 0px;
              }
              .pageBreak {
                page-break-before: always;
                margin-top: 50px;
                margin-bottom: 50px;
                border-bottom: none !important;
              }
              header {
                position: fixed;
                width: 100%;
                top: 0;
                left: 0;
                right: 0;
                z-index: 9999;
                background-color: white !important;
                height: 2.3cm;
              }
              footer {
                position: fixed;
                width: 100%;
                bottom: 0;
                left: 0;
                right: 0;
                z-index: 9999;
                padding: 1cm;
                padding-top: 0cm;
                background-color: white;
              }
              .header-space {
                height: 2.2cm;
                background-color: white !important;
              }
              .footer-spacer {
                height: 2cm;
                width: 100%;
                background-color: white !important;
              }
            }
            .sectionTitle {
              font-weight: 600;
              color: #4b8b40;
            }
            .headerTable {
              width: 100%;
              background: url('${newLogo}');
              background-size: 100%; 
              text-align: right; 
              color: white; 
              padding-top: 12px; 
              font-weight: 600; 
              height: 70px; 
              background-repeat: no-repeat;
            }
            .table {
              margin-bottom: 20px;
              page-break-inside: avoid;
            }
            .techniques {
              page-break-inside: auto;
            }
            .table {
              width: 100%;
              border-collapse: collapse;
            }
            .table thead th {
              text-transform: capitalize;
              background-color: #00a3e0;
              color: white;
            }
            .table th, 
            .table td {
              text-align: left;
              padding: 5px;
              border-bottom: 0.5px solid #00a3e0;
              border-right: 0.5px solid #00a3e0;
              vertical-align: top;
            }
            .titleWidth{
              width: 120px;
            }
            .print-hidden {
              visibility: hidden;
              display: none;
              padding: 0px !important;
              margin: 0px !important;
            }
            .table th:last-child,
            .table td:last-child {
              border-right: none;
              border-bottom: 0.5px solid #00a3e0;
            }
            .table tr:nth-child(odd) {
              background-color: #c6e7f5;
            }

            body {
              padding: 0px;
              margin: 0px;
              font-family: Arial, Helvetica, sans-serif;
            }
            .pageContent {
              padding: 1cm;
            }
            #printSection {
              max-width: 240mm;
              background-color: white;
              color: rgba(0, 0, 0, 0.8);
            }
            .titleHolder {
              position: absolute;
              right: -20px;
              top: -12px;
              width: 308px;
              height: 70px;
              max-width: 340px;
            }
            .titleBox {
              top: 50%;
              transform: translate(0, -50%);
              position: absolute;
              right: 0px;
              font-size: 14pt;
              line-height: 14pt;
              padding-right: 10px;
            }
        </style>
        </head>
        <body>
          <div>
            <header>
              <div class="headerTable">
                <div style="margin-right: 20px; padding-top: 5px; position: relative">
                  <div class="titleHolder">
                    <div class="titleBox">
                      ${title} Details
                      <div style="font-size: 11pt">Vectra Mitre Att&amp;CK</div>
                    </div>
                  </div>
                </div>
              </div>
            </header>
            <table class="reportContent">
              <thead>
                <tr>
                  <td>
                    <div class="header-space"></div>
                  </td>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td class="pageContent">
                    ${content}
                  </td>
                </tr>
              </tbody>
              <tfoot>
                <tr>
                  <td>
                    <div class="footer-spacer"></div>
                  </td>
                </tr>
              </tfoot>
            </table>
            <footer>
              <table style="background-color: white !important; width: 100%">
                <tr>
                  <td style="font-size: 10px; line-height: 12px">
                    &copy;{{ currentYear }} Vectra AI, Inc. All rights reserved. Vectra,
                    the Vectra AI logo, Cognito and Security that thinks are registered
                    trademarks and Cognito Detect, Cognito Recall, Cognito Stream, the
                    Vectra Threat Labs and the Threat Certainty Index are trademarks of
                    Vectra AI. Other brand, product and service names are trademarks,
                    registered trademarks or service marks of their respective holders.
                  </td>
                </tr>
              </table>
            </footer>
          </div>
        </body>`;

      document +=
        `<script>setTimeout(function () {
                window.close();
        }, 10000);</sc` + `ript>`;

      document += "</html>";

      console.log(document);

      mywindow.document.write(document);

      mywindow.document.close(); // necessary for IE >= 10
      mywindow.focus(); // necessary for IE >= 10*/

      mywindow.print();

      return true;
    },
  },
};
