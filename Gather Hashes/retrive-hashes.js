function onlyUnique(value, index, array) {
  return array.indexOf(value) === index;
}

hashes = []

if (window.location.href.includes("tria.ge")){//TRIAGE
	x = document.getElementsByClassName("clipboard")
	for (i=0; i<x.length; i++){
		hashes.push(x[i].childNodes[1].dataset.clipboard)
	}
}else{//MALWAREBAZAAR
	x = document.getElementsByClassName("shortify")
	for (i=0; i<x.length; i++){
		hashes.push(x[i].innerHTML)
	}
}

var uniqueHashes = hashes.filter(onlyUnique);
console.log(uniqueHashes)