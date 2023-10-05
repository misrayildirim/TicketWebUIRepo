var albania = ["Tirana", "Durres", "Vlore", "Shkoder"];
var kosovo = ["Prishtina", "Mitrovica", "Peje", "Gjakove"];
var germany = ["Berlin", "Frankfurt", "Hannover", "Bonn"];


document.getElementById("1").addEventListener("change", function (e) {
    var select2 = document.getElementById("2");
    select2.innerHTML = "";
    var aItems = [];
    if (this.value == "2") {
        aItems = kosovo;
    } else if (this.value == "3") {
        aItems = germany;
    } else if (this.value == "1") {
        aItems = albania;
    }
    for (var i = 0, len = aItems.length; i < len; i++) {
        var option = document.createElement("option");
        option.value = (i + 1);
        var textNode = document.createTextNode(aItems[i]);
        option.appendChild(textNode);
        select2.appendChild(option);
    }

}, false);