const EP = window.ORDERS_ENDPOINTS;

// Lista
async function cargarLista(){
  const res = await fetch(EP.list);
  const data = await res.json();
  // ... render como ya lo tienes
}

// Detalle
async function verPedido(id){
  const res = await fetch(EP.detail(id));
  const p = await res.json();
  // ... render modal
}

// Crear
async function crearPedido(payload){
  const res = await fetch(EP.create, {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)
  });
  // ...
}

// Cambiar estatus (Recibir)
async function recibirPedido(id){
  const res = await fetch(EP.patchStatus(id), {
    method:'PATCH', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ estatus: 'RECIBIDO' })
  });
  // ...
}

// Catálogos
async function cargarCatalogos(){
  const [prov, far] = await Promise.all([
    fetch("{% url 'prov_all' %}") /* si tienes esta url de Django */,
    fetch(EP.farmacias),
  ]);
  // o si no tienes prov_all como URL Django:
  const provRes = await fetch("{% url 'suppliers' %}"); // ajusta según tu ruteo
}
