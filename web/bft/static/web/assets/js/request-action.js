// function startserver() {
//     let val_server = $('#servernum').val();
//     recoverPriPoly(val_server);
// }

function startclient() {
  let clientnum = $('#clientnum').val();
  let xhr = new XMLHttpRequest();
  xhr.open('GET', `http://127.0.0.1:8888/cmds?n=${clientnum}`, true);
  xhr.responseType = 'json';
  xhr.onreadystatechange = function () {
    if (xhr.readyState == 4 && this.status == 200) {
      let res = this.response;
      let { code, data } = res;
      if (code == 0) {
        $('.error-msg').remove();
        $('.res-result').append(`<span>结果</span>`);
        $('.res-result').append(`<p>${data}</p>`);
      } else {
        $('.res-result').append(`<span class="error-msg">${data}</span>`);
      }
    }
  };
  xhr.send();
}

function recoverPriPoly(n) {
  let xhr = new XMLHttpRequest();
  xhr.open('GET', `http://127.0.0.1:8888/recover_pri_poly?n=${n}`, true);
  xhr.responseType = 'json';
  xhr.onreadystatechange = function () {
    if (xhr.readyState == 4 && this.status == 200) {
      let res = this.response;
      let { code, data } = res;
      if (code == 0) {
        $('.error-msg').remove();
        var lista = [];
        var listrecovered = [];
        var listreverseRecovered = [];
        for (let index = 0; index < data.a.length; index++) {
          const a = data.a[index];
          const recovered = data.recovered[index];
          const reverseRecovered = data.reverseRecovered[index];
          lista.push(`<p>a-${index}：${a}</p>`);
          listrecovered.push(`<p>recovered-${index}：${recovered}</p>`);
          listreverseRecovered.push(
            `<p>reverseRecovered-${index}：${reverseRecovered}</p>`
          );
        }
        $('.res-result').append(`<span>t：${data.t}</span>`);
        $('.res-result').append(lista);
        $('.res-result').append(listrecovered);
        $('.res-result').append(listreverseRecovered);
      } else {
        $('.res-result').append(`<span class="error-msg">${data}</span>`);
      }
    }
  };
  xhr.send();
}

let socket;
(function startSocket() {
  socket = new WebSocket(`ws://127.0.0.1:8888/ws`);

  socket.onopen = () => {
    console.log('连接成功');
  };

  socket.onmessage = (value) => {
    let res = JSON.parse(value.data);
    let type_client_server = res.type_client_server
    ///if (res.code == 0) {
    // $('.res-result').append(`<p>${res.data}</p>`);
    // } else {
    // $('.res-result').append(`<p>${res.data}</p>`);
    // }

    console.log(res)
    
    if (res.type_client_server == "1") {
      $('.res-result1').append(`<p>服务器：${res.data}</p>`);
    } else {
      $('.res-result2').append(`<p>客户端：${res.data}</p>`);
    }

  };

  socket.onclose = (event) => {
    console.log('关闭连接: ', event);
    socket.send('Client Closed!');
  };

  socket.onerror = (error) => {
    console.log('报错了: ', error);
  };
})();

// 
function startclientByWs() {
  let clientID = $('#clientID').val();
  let msg = JSON.stringify({
    num: clientID,
    type: "0",
  });
  console.log('发送client: ')
  console.log(msg)
  socket.send(msg);
}

function startserverByWS() {
  let servernum = $('#servernum').val();
  let msg = JSON.stringify({
    num: servernum,
    type: "1",
  });
  socket.send(msg);
}
