$(document).ready(function () {
  $(".terminal-submit").click(function () {
    var reportId = $("#reportId").val();
    var reportUrl = $("#reportUrl").val();
    var bugReport = $("#bugReport").val();

    var data = {
      id: reportId,
      url: reportUrl,
      report: bugReport,
    };

    $.ajax({
      type: "POST",
      url: "/report_bug",
      contentType: "application/json",
      data: JSON.stringify(data),
      success: function (response) {
        $("body").html(response);
      },
      error: function (xhr, status, error) {
        alert("Error submitting report: " + error);
      },
    });
  });
});

$(document).ready(function() {
  if ($('.message-container').length) {
      setTimeout(function() {
          $('.message-container').remove();
      }, 3000);
  }
});
