(this["webpackJsonpmy-react-app"]=this["webpackJsonpmy-react-app"]||[]).push([[0],{29:function(e,t,n){},37:function(e,t,n){},38:function(e,t,n){"use strict";n.r(t);n(24);var c=n(1),i=n.n(c),s=n(18),a=n.n(s),r=(n(29),n(19)),u=n(20),l=n(23),o=n(22),m=n(9),j=n(2),d=n(0),b=function(){return Object(d.jsxs)(d.Fragment,{children:[Object(d.jsx)("h1",{children:"Hello, welcome to my blog!"}),Object(d.jsx)("p",{children:"Welcome to my blog! Proin congue ligula id risus posuere, vel eleifend ex egestas. Sed in turpis leo. Aliquam malesuada in massa tincidunt egestas. Nam consectetur varius turpis, non porta arcu porttitor non. In tincidunt vulputate nulla quis egestas. Ut eleifend ut ipsum non fringilla. Praesent imperdiet nulla nec est luctus, at sodales purus euismod."}),Object(d.jsx)("p",{children:"Donec vel mauris lectus. Etiam nec lectus urna. Sed sodales ultrices dapibus. Nam blandit tristique risus, eget accumsan nisl interdum eu. Aenean ac accumsan nisi. Nunc vel pulvinar diam. Nam eleifend egestas viverra. Donec finibus lectus sed lorem ultricies, eget ornare leo luctus. Morbi vehicula, nulla eu tempor interdum, nibh elit congue tellus, ac vulputate urna lorem nec nisi. Morbi id consequat quam. Vivamus accumsan dui in facilisis aliquet.,"}),Object(d.jsx)("p",{children:"Etiam nec lectus urna. Sed sodales ultrices dapibus. Nam blandit tristique risus, eget accumsan nisl interdum eu. Aenean ac accumsan nisi. Nunc vel pulvinar diam. Nam eleifend egestas viverra. Donec finibus lectus sed lorem ultricies, eget ornare leo luctus. Morbi vehicula, nulla eu tempor interdum, nibh elit congue tellus, ac vulputate urna lorem nec nisi. Morbi id consequat quam. Vivamus accumsan dui in facilisis aliquet.,"})]})},p=function(){return Object(d.jsxs)(d.Fragment,{children:[Object(d.jsx)("h1",{children:"About me"}),Object(d.jsx)("p",{children:"Welcome to my blog! Proin congue ligula id risus posuere, vel eleifend ex egestas. Sed in turpis leo. Aliquam malesuada in massa tincidunt egestas. Nam consectetur varius turpis, non porta arcu porttitor non. In tincidunt vulputate nulla quis egestas. Ut eleifend ut ipsum non fringilla. Praesent imperdiet nulla nec est luctus, at sodales purus euismod."}),Object(d.jsx)("p",{children:"Donec vel mauris lectus. Etiam nec lectus urna. Sed sodales ultrices dapibus. Nam blandit tristique risus, eget accumsan nisl interdum eu. Aenean ac accumsan nisi. Nunc vel pulvinar diam. Nam eleifend egestas viverra. Donec finibus lectus sed lorem ultricies, eget ornare leo luctus. Morbi vehicula, nulla eu tempor interdum, nibh elit congue tellus, ac vulputate urna lorem nec nisi. Morbi id consequat quam. Vivamus accumsan dui in facilisis aliquet.,"}),Object(d.jsx)("p",{children:"Etiam nec lectus urna. Sed sodales ultrices dapibus. Nam blandit tristique risus, eget accumsan nisl interdum eu. Aenean ac accumsan nisi. Nunc vel pulvinar diam. Nam eleifend egestas viverra. Donec finibus lectus sed lorem ultricies, eget ornare leo luctus. Morbi vehicula, nulla eu tempor interdum, nibh elit congue tellus, ac vulputate urna lorem nec nisi. Morbi id consequat quam. Vivamus accumsan dui in facilisis aliquet.,"})]})},h=n(4),f=n.n(h),O=n(8),v=n(10),x=function(e){var t=e.articles,n=void 0===t?[]:t;return Object(d.jsx)(d.Fragment,{children:n&&n.length>0?n.map((function(e,t){return Object(d.jsxs)(m.b,{className:"article-list-item",to:"/article/".concat(e.name),children:[Object(d.jsx)("h3",{children:e.title}),Object(d.jsxs)("p",{children:[e.content[0].substring(0,150),"..."]})]},t)})):"Loading..."})},g=function(){var e=Object(c.useState)({name:"",title:"",content:[],upvotes:0,comments:[]}),t=Object(v.a)(e,2),n=t[0],i=t[1];return Object(c.useEffect)((function(){(function(){var e=Object(O.a)(f.a.mark((function e(){var t,n;return f.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,fetch("/api/articles");case 2:return t=e.sent,e.next=5,t.json();case 5:n=e.sent,i(n);case 7:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}})()()}),[]),Object(d.jsxs)(d.Fragment,{children:[Object(d.jsx)("h1",{children:"Articles"}),Object(d.jsx)(x,{articles:n})]})},N=function(e){var t=e.comments;return Object(d.jsxs)(d.Fragment,{children:[Object(d.jsx)("h3",{children:"Comments:"}),t.map((function(e,t){return Object(d.jsxs)("div",{className:"comment",children:[Object(d.jsx)("h4",{children:e.username}),Object(d.jsx)("p",{children:e.text})]},t)}))]})},q=function(e){var t=e.articleName,n=e.upvotes,c=e.setArticleInfo,i=function(){var e=Object(O.a)(f.a.mark((function e(){var n,i;return f.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,fetch("/api/articles/".concat(t,"/upvote"),{method:"post"});case 2:return n=e.sent,e.next=5,n.json();case 5:i=e.sent,c(i);case 7:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}();return Object(d.jsxs)("div",{id:"upvotes-section",children:[Object(d.jsx)("button",{onClick:function(){return i()},children:"Add Upvote"}),Object(d.jsxs)("p",{children:["This post has been upvoted ",n," times"]})]})},A=function(e){var t=e.articleName,n=e.setArticleInfo,i=Object(c.useState)(""),s=Object(v.a)(i,2),a=s[0],r=s[1],u=Object(c.useState)(""),l=Object(v.a)(u,2),o=l[0],m=l[1],j=function(){var e=Object(O.a)(f.a.mark((function e(){var c,i;return f.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,fetch("/api/articles/".concat(t,"/add-comment"),{method:"post",body:JSON.stringify({username:a,text:o}),headers:{"Content-Type":"application/json"}});case 2:return c=e.sent,e.next=5,c.json();case 5:i=e.sent,n(i),r(""),m("");case 9:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}();return Object(d.jsxs)("div",{id:"add-comment-form",children:[Object(d.jsx)("h3",{children:"Add a Comment"}),Object(d.jsxs)("label",{children:["Name:",Object(d.jsx)("input",{type:"text",value:a,onChange:function(e){return r(e.target.value)}})]}),Object(d.jsxs)("label",{children:["Comment:",Object(d.jsx)("textarea",{rows:"4",cols:"50",value:o,onChange:function(e){return m(e.target.value)}})]}),Object(d.jsx)("button",{onClick:function(){return j()},children:"Add Comment"})]})},y=function(){return Object(d.jsx)("h1",{children:"404: Page Not Found"})},w=function(e){var t=e.match.params.name,n=Object(c.useState)({name:"",title:"",content:[],upvotes:0,comments:[]}),i=Object(v.a)(n,2),s=i[0],a=i[1];Object(c.useEffect)((function(){(function(){var e=Object(O.a)(f.a.mark((function e(){var t,n;return f.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,fetch("/api/articles");case 2:return t=e.sent,e.next=5,t.json();case 5:n=e.sent,a(n);case 7:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}})()()}),[]);var r=Object(c.useState)({upvotes:0,comments:[]}),u=Object(v.a)(r,2),l=u[0],o=u[1];if(Object(c.useEffect)((function(){(function(){var e=Object(O.a)(f.a.mark((function e(){var n,c;return f.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,fetch("/api/articles/".concat(t));case 2:return n=e.sent,e.next=5,n.json();case 5:c=e.sent,o(c);case 7:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}})()()}),[t]),s&&s.length>0){var m=s.find((function(e){return e.name===t}));if(!m)return Object(d.jsx)(y,{});var j=s.filter((function(e){return e.name!==t}));return Object(d.jsxs)(d.Fragment,{children:[Object(d.jsx)("h1",{children:m.title}),Object(d.jsx)(q,{articleName:t,upvotes:l.upvotes,setArticleInfo:o}),m.content.map((function(e,t){return Object(d.jsx)("p",{children:e},t)})),Object(d.jsx)(N,{comments:l.comments}),Object(d.jsx)(A,{articleName:t,setArticleInfo:o}),Object(d.jsx)("h3",{children:"Other Articles:"}),Object(d.jsx)(x,{articles:j})]})}return Object(d.jsx)(d.Fragment,{children:"Loading..."})},S=function(){return Object(d.jsx)("nav",{children:Object(d.jsxs)("ul",{children:[Object(d.jsx)("li",{children:Object(d.jsx)(m.b,{to:"/",children:"Home"})}),Object(d.jsx)("li",{children:Object(d.jsx)(m.b,{to:"/about",children:"About"})}),Object(d.jsx)("li",{children:Object(d.jsx)(m.b,{to:"/articles-list",children:"Articles"})})]})})},C=(n(37),function(e){Object(l.a)(n,e);var t=Object(o.a)(n);function n(){return Object(r.a)(this,n),t.apply(this,arguments)}return Object(u.a)(n,[{key:"render",value:function(){return Object(d.jsx)(m.a,{children:Object(d.jsxs)("div",{className:"App",children:[Object(d.jsx)(S,{}),Object(d.jsx)("div",{id:"page-body",children:Object(d.jsxs)(j.c,{children:[Object(d.jsx)(j.a,{path:"/",component:b,exact:!0}),Object(d.jsx)(j.a,{path:"/about",component:p}),Object(d.jsx)(j.a,{path:"/articles-list",component:g}),Object(d.jsx)(j.a,{path:"/article/:name",component:w}),Object(d.jsx)(j.a,{component:y})]})})]})})}}]),n}(c.Component)),F=function(e){e&&e instanceof Function&&n.e(3).then(n.bind(null,39)).then((function(t){var n=t.getCLS,c=t.getFID,i=t.getFCP,s=t.getLCP,a=t.getTTFB;n(e),c(e),i(e),s(e),a(e)}))};a.a.render(Object(d.jsx)(i.a.StrictMode,{children:Object(d.jsx)(C,{})}),document.getElementById("root")),F()}},[[38,1,2]]]);