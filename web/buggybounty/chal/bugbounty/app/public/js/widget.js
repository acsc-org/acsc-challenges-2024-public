var params = Arg.parse(location.search);
if (params.highlight) {
  var products = document.querySelectorAll(".product");
  products.forEach(function (product) {
    product.style.backgroundColor = "";
  });
  var productToHighlight = document.getElementById(
    "product" + params.highlight
  );
  if (productToHighlight) {
    productToHighlight.style.backgroundColor = "yellow";
  }
}
