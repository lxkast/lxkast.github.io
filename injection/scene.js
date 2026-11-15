import * as THREE from 'three';

const V = (x, y, z) => new THREE.Vector3(x, y, z);
const up = V(0, 1, 0);
const sphere = new THREE.SphereGeometry(1, 28, 18);
const cylinder = new THREE.CylinderGeometry(1, 1, 1, 32);
const box = new THREE.BoxGeometry(1, 1, 1);

function material(color, roughness = .7, metalness = 0) {
  return new THREE.MeshStandardMaterial({ color, roughness, metalness });
}

function part(parent, geometry, mat, size, center = [0, 0, 0]) {
  const mesh = new THREE.Mesh(geometry, mat);
  mesh.position.set(...center);
  mesh.scale.set(...size);
  mesh.castShadow = mesh.receiveShadow = true;
  parent.add(mesh);
  return mesh;
}

function aimLink(mesh, a, b) {
  const axis = b.clone().sub(a);
  mesh.position.copy(a).lerp(b, .5);
  mesh.scale.y = axis.length();
  mesh.quaternion.setFromUnitVectors(up, axis.normalize());
}

function skinUV(spec) {
  const width = 1.5;
  const min = spec.elbow_z == null ? -1.65 : -2.1;
  const max = spec.elbow_z == null ? 1.65 : spec.profile.at(-1)[0] + .12;
  return { width, x: x => x / width + .5, z: z => (z - min) / (max - min) };
}

function skinSurface(profile, x, z) {
  for (let i = 1; i < profile.length; i++) {
    const a = profile[i - 1], b = profile[i];
    if (a[0] <= z && z <= b[0]) {
      const t = (z - a[0]) / (b[0] - a[0]);
      const width = THREE.MathUtils.lerp(a[1], b[1], t);
      if (width <= Math.abs(x)) return -Infinity;
      const center = THREE.MathUtils.lerp(a[2], b[2], t);
      const height = THREE.MathUtils.lerp(a[3], b[3], t);
      return center + height * Math.sqrt(1 - (x / width) ** 2);
    }
  }
  return -Infinity;
}

function buriedNeedleSpan(profile, tip, hub) {
  const buried = t => {
    const point = tip.clone().lerp(hub, t);
    return point.y < skinSurface(profile, point.x, point.z);
  };
  const samples = 64;
  let start = buried(0) ? 0 : null;
  let end = null;
  let previous = buried(0);
  for (let i = 1; i <= samples; i++) {
    const current = buried(i / samples);
    if (current !== previous) {
      let low = (i - 1) / samples, high = i / samples;
      for (let j = 0; j < 8; j++) {
        const middle = (low + high) / 2;
        if (buried(middle) === previous) low = middle;
        else high = middle;
      }
      const boundary = (low + high) / 2;
      if (current && start === null) start = boundary;
      if (!current && start !== null) { end = boundary; break; }
    }
    previous = current;
  }
  return start === null ? null : [start, end ?? 1];
}

function skinTexture(spec, uv) {
  const canvas = document.createElement('canvas');
  canvas.width = 600;
  canvas.height = spec.elbow_z == null ? 1100 : 2700;
  const ctx = canvas.getContext('2d');
  const pixelX = x => uv.x(x) * canvas.width;
  const pixelY = z => uv.z(z) * canvas.height;
  const skinRGB = [1, 3, 5].map(i => parseInt(spec.skin.slice(i, i + 2), 16));
  const shade = factors => skinRGB.map((value, i) => Math.min(255, Math.round(value * factors[i]))).join(',');
  const tone = (skinRGB[0] * .299 + skinRGB[1] * .587 + skinRGB[2] * .114) / 255;
  let seed = spec.texture_seed;
  const random = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed / 2 ** 32;
  };

  ctx.fillStyle = spec.skin;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  for (let i = 0; i < (spec.elbow_z == null ? 170 : 360); i++) {
    const x = random() * canvas.width;
    const y = random() * canvas.height;
    const r = 18 + random() * 85;
    const hue = spec.phenotype
      ? shade(random() < .52 ? [.87, .78, .76] : [1.05, 1.05, 1.04])
      : random() < .52 ? '137,65,52' : '255,215,175';
    const wash = ctx.createRadialGradient(x, y, 0, x, y, r);
    wash.addColorStop(0, `rgba(${hue}, .10)`);
    wash.addColorStop(1, `rgba(${hue}, 0)`);
    ctx.fillStyle = wash;
    ctx.fillRect(x - r, y - r, 2 * r, 2 * r);
  }

  const palm = ctx.createRadialGradient(pixelX(0), pixelY(-1.21), 1, pixelX(0), pixelY(-1.21), 115);
  palm.addColorStop(0, spec.phenotype ? `rgba(${shade([1.09, .98, .96])},.27)` : 'rgba(255,188,155,.50)');
  palm.addColorStop(1, spec.phenotype ? `rgba(${shade([1.05, .95, .94])},0)` : 'rgba(251,161,138,0)');
  ctx.fillStyle = palm;
  ctx.fillRect(0, pixelY(-1.62), canvas.width, 275);

  // Each stamp uses the cover above the vein wall, rather than the centerline
  // depth. A deep vessel is faint even if it is wide or crosses another vessel.
  for (const [index, vein] of spec.veins.entries()) {
    for (const [x, , z, radius, depth] of vein) {
      const px = pixelX(x);
      const py = pixelY(z);
      const cover = Math.max(0, depth - radius);
      const r = (radius * 1.25 + Math.min(cover, .06) * .24) * canvas.width / uv.width;
      const opacity = spec.phenotype
        ? .50 * Math.exp(-Math.pow(cover / .045, 1.5))
          * (.85 + .15 * tone) * (index === 2 ? 1 : .9)
        : spec.elbow_z == null
        ? (.132 + .088 * (radius / .034)) * Math.exp(-7.5 * depth) * (index ? .76 : 1)
        : .24 * Math.exp(-13 * depth) * (index === 2 ? 1 : .78);
      const color = spec.phenotype ? shade([.45, .86, 1.16]) : '66,105,112';
      const middle = spec.phenotype ? shade([.62, .90, 1.09]) : '77,112,115';
      const outer = spec.phenotype ? shade([.83, .94, 1.02]) : '100,125,120';
      const tint = ctx.createRadialGradient(px, py, 0, px, py, r);
      tint.addColorStop(0, `rgba(${color},${opacity})`);
      tint.addColorStop(.45, `rgba(${middle},${opacity * .60})`);
      tint.addColorStop(1, `rgba(${outer},0)`);
      ctx.fillStyle = tint;
      ctx.fillRect(px - r, py - r, 2 * r, 2 * r);
    }
  }

  ctx.lineCap = 'round';
  const creases = [
    [[-.18, -1.34], [-.04, -1.26], [.07, -1.28], [.18, -1.32]],
    [[-.19, -1.24], [-.10, -1.16], [.02, -1.12], [.10, -1.16]],
    [[-.10, -1.32], [.01, -1.27], [.07, -1.14], [.015, -1.055]],
    [[-.17, -.94], [-.06, -.928], [.08, -.927], [.18, -.94]],
    [[-.14, -.90], [-.05, -.886], [.07, -.887], [.14, -.902]],
  ];
  if (spec.elbow_z != null) {
    const z = spec.elbow_z;
    creases.push(
      [[-.30, z + .008], [-.14, z - .045], [.10, z - .035], [.29, z + .018]],
      [[-.21, z + .058], [-.10, z + .031], [.08, z + .042], [.20, z + .067]],
    );
  }
  for (const [a, b, c, d] of creases) {
    ctx.beginPath();
    ctx.moveTo(pixelX(a[0]), pixelY(a[1]));
    ctx.bezierCurveTo(pixelX(b[0]), pixelY(b[1]), pixelX(c[0]), pixelY(c[1]), pixelX(d[0]), pixelY(d[1]));
    ctx.strokeStyle = 'rgba(116,53,40,.24)';
    ctx.lineWidth = 2.1;
    ctx.stroke();
  }

  for (let i = 0; i < (spec.elbow_z == null ? 22500 : 50000); i++) {
    const x = random() * canvas.width;
    const y = random() * canvas.height;
    const r = .35 + random() * 1.05;
    ctx.fillStyle = random() < .5 ? 'rgba(85,46,34,.10)' : 'rgba(255,222,193,.13)';
    ctx.fillRect(x, y, r, r);
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = 4;
  return texture;
}

function ringMesh(length, sample, transform) {
  const sides = 64;
  const points = [], uv = [], indices = [];
  for (let i = 0; i <= length; i++) {
    for (let j = 0; j <= sides; j++) {
      const [x, y, z] = sample(i / length, j / sides * Math.PI * 2);
      points.push(x, y, z);
      uv.push(transform.x(x), 1 - transform.z(z));
      if (i < length && j < sides) {
        const a = i * (sides + 1) + j;
        const b = a + sides + 1;
        indices.push(a, a + 1, b, a + 1, b + 1, b);
      }
    }
  }
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.Float32BufferAttribute(points, 3));
  geo.setAttribute('uv', new THREE.Float32BufferAttribute(uv, 2));
  geo.setIndex(indices);
  geo.computeVertexNormals();
  const normals = geo.getAttribute('normal');
  for (let i = 0; i <= length; i++) {
    const first = i * (sides + 1);
    const last = first + sides;
    const normal = V().fromBufferAttribute(normals, first).add(V().fromBufferAttribute(normals, last)).normalize();
    normals.setXYZ(first, normal.x, normal.y, normal.z);
    normals.setXYZ(last, normal.x, normal.y, normal.z);
  }
  return geo;
}

function patient(scene, spec) {
  const uv = skinUV(spec);
  const fullArm = spec.elbow_z != null;
  const skin = new THREE.MeshStandardMaterial({ map: skinTexture(spec, uv), roughness: .86 });
  const fingertip = material(spec.skin, .86);
  const profile = spec.profile;
  const start = profile[0][0];
  const end = profile.at(-1)[0];
  const arm = ringMesh(fullArm ? 620 : 132, (t, angle) => {
    const z = THREE.MathUtils.lerp(start, end, t);
    const i = t === 1 ? profile.length - 1 : Math.max(1, profile.findIndex(row => row[0] >= z));
    const [a, b] = [profile[i - 1], profile[i]];
    const mix = (z - a[0]) / (b[0] - a[0]);
    const [w, c, h] = a.slice(1).map((n, j) => THREE.MathUtils.lerp(n, b[j + 1], mix));
    return [w * Math.cos(angle), c + h * Math.sin(angle), z];
  }, uv);
  part(scene, arm, skin, [1, 1, 1]);
  part(scene, sphere, skin, [.027, .024, .024], [0, profile.at(-1)[2], end - .003]);
  const [, palmWidth, palmCenter, palmHeight] = profile[0];
  part(scene, sphere, skin, [palmWidth, palmHeight, .085], [0, palmCenter, start + .043]);

  const fingers = fullArm ? [
    [-.245, -1.80, -.12, -.79, .064],
    [-.111, -1.91, -.05, -.85, .074],
    [.037, -1.93, .016, -.87, .076],
    [.184, -1.87, .103, -.75, .072],
    [.268, -1.45, .302, -.52, .101],
  ] : [
    [-.188, -1.355, -.095, -.40, .049],
    [-.102, -1.409, -.04, -.53, .060],
    [.006, -1.428, .012, -.58, .063],
    [.120, -1.379, .067, -.49, .061],
    [.183, -1.168, .207, -.291, .086],
  ];
  for (const [x, z, dx, dz, r] of fingers) {
    const side = V(-dz, 0, dx).normalize();
    const geo = ringMesh(34, (t, angle) => {
      const radius = r * (.97 - .27 * t) * Math.sqrt(Math.max(.0001, 1 - ((t - .48) / .52) ** 8));
      const lateral = Math.cos(angle) * radius;
      return [x + dx * t + side.x * lateral, .21 - .052 * t + .011 * Math.sin(t * Math.PI) + Math.sin(angle) * radius * .78,
        z + dz * t + side.z * lateral];
    }, uv);
    // Fingers run toward -z, so the outward normal is reversed by the ring order.
    const index = geo.index.array;
    for (let i = 0; i < index.length; i += 3) [index[i + 1], index[i + 2]] = [index[i + 2], index[i + 1]];
    geo.computeVertexNormals();
    part(scene, geo, fingertip, [1, 1, 1]);
  }
}

function veinGeometry(scene, veins) {
  const mat = new THREE.MeshBasicMaterial({ color: '#5fcac6', depthTest: false });
  for (const points of veins) {
    const vertices = [], indices = [];
    const sides = 12;
    points.forEach(([x, y, z, radius], i) => {
      const center = V(x, y, z);
      const a = V(...points[Math.max(0, i - 1)].slice(0, 3));
      const b = V(...points[Math.min(points.length - 1, i + 1)].slice(0, 3));
      const tangent = b.sub(a).normalize();
      const side = up.clone().cross(tangent).normalize();
      const normal = tangent.clone().cross(side);
      for (let j = 0; j < sides; j++) {
        const theta = j / sides * 2 * Math.PI;
        vertices.push(...center.clone().addScaledVector(side, radius * Math.cos(theta))
          .addScaledVector(normal, radius * Math.sin(theta)).toArray());
        if (i === points.length - 1) continue;
        const start = i * sides;
        const next = (j + 1) % sides;
        indices.push(start + j, start + next, start + j + sides,
          start + next, start + next + sides, start + j + sides);
      }
    });
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
    geo.setIndex(indices);
    const vein = new THREE.Mesh(geo, mat);
    vein.layers.set(1);
    vein.renderOrder = 5;
    scene.add(vein);
  }
}

function table(scene, fullArm) {
  if (fullArm) {
    part(scene, box, material('#586b77'), [14.0, .25, 13.0], [0, -.128, 1.2]);
    part(scene, box, material('#476c73'), [2.50, .035, 8.75], [0, -.0175, 1.22]);
    const seam = material('#577e82');
    for (const x of [-1.21, 1.21]) part(scene, box, seam, [.012, .001, 8.65], [x, .001, 1.22]);
    for (const z of [-3.11, 5.55]) part(scene, box, seam, [2.43, .001, .012], [0, .001, z]);
    return;
  }
  part(scene, box, material('#586b77'), [8, .12, 7], [0, -.08, 0]);
  const mat = material('#476c73');
  part(scene, box, mat, [1.52, .025, 4.09], [0, -.004, -.12]);
  const stitch = material('#577e82');
  for (const x of [-.725, .725]) {
    part(scene, box, stitch, [.008, .001, 3.99], [x, .009, -.12]);
  }
  for (const z of [-2.115, 1.875]) {
    part(scene, box, stitch, [1.45, .001, .008], [0, .009, z]);
  }
}

function robot(scene, length, diameter, calibration, dimensions = {}, profile) {
  const radii = dimensions.link_radii ?? {
    upper_link: .103, lower_link_elbow: .083, lower_link_wrist: .083, wrist_collar: .047,
  };
  const taperStart = dimensions.lower_taper_start ?? .70;
  const shell = material('#dde5e9', .32, .15);
  const metal = material('#8199a8', .35, .55);
  const dark = material('#233a48', .44, .25);
  const darkGlass = material('#10232d', .2, .2);
  const accent = material('#3c8e93', .30, .16);
  const chrome = material('#ccd9e1', .23, .65);
  const base = new THREE.Group();
  scene.add(base);
  part(base, cylinder, dark, [.23, .075, .23], [0, .037, 0]);
  part(base, cylinder, shell, [.175, .18, .175], [0, .135, 0]);
  part(base, cylinder, metal, [.135, .205, .135], [0, .292, 0]);

  const upper = part(scene, cylinder, shell, [radii.upper_link, 1, radii.upper_link]);
  const lower = part(scene, cylinder, shell, [radii.lower_link_elbow, 1, radii.lower_link_elbow]);
  const neck = part(scene, new THREE.CylinderGeometry(radii.lower_link_wrist, radii.lower_link_elbow, 1, 32),
    shell, [1, 1, 1]);
  const collar = part(scene, cylinder, metal, [radii.wrist_collar, 1, radii.wrist_collar]);
  const joints = [.127, .111, dimensions.wrist_joint_radius ?? (dimensions.link_radii ? radii.lower_link_wrist : .063)]
    .map(r => part(scene, sphere, dark, [r, r, r]));
  const caps = [.085, .072].map(r => {
    const cap = part(scene, cylinder, accent, [r, .018, r]);
    cap.rotation.z = Math.PI / 2;
    return cap;
  });

  const tool = new THREE.Group();
  scene.add(tool);
  const gripRadius = dimensions.grip_radius ?? (dimensions.link_radii ? .025 : .035);
  const grip = part(tool, cylinder, accent, [gripRadius, .09, gripRadius], [0, 0, -length - .012]);
  grip.rotation.x = Math.PI / 2;
  const radius = diameter / 2;
  const pointLength = radius * 3.5;
  const steel = part(tool, cylinder, chrome, [radius, length - pointLength, radius], [0, 0, -(length + pointLength) / 2]);
  steel.rotation.x = Math.PI / 2;
  const point = part(tool, new THREE.ConeGeometry(radius, pointLength, 16), chrome, [1, 1, 1], [0, 0, -pointLength / 2]);
  point.rotation.x = Math.PI / 2;
  // Color copies of the exact needle geometry, clipped to the buried span.
  // Layer 3 is enabled only on the workbench, never on agent RGB cameras.
  const hiddenNeedle = new THREE.ShaderMaterial({
    uniforms: {
      tipWorld: { value: V(0, 0, 0) },
      axisWorld: { value: V(0, 0, 1) },
      buriedStart: { value: 0 },
      buriedEnd: { value: 0 },
      color: { value: new THREE.Color('#ff5dbb') },
    },
    vertexShader: `
      uniform vec3 tipWorld, axisWorld;
      varying float distanceFromTip;
      void main() {
        vec4 world = modelMatrix * vec4(position, 1.0);
        distanceFromTip = -dot(world.xyz - tipWorld, axisWorld);
        gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
      }
    `,
    fragmentShader: `
      uniform float buriedStart, buriedEnd;
      uniform vec3 color;
      varying float distanceFromTip;
      void main() {
        if (distanceFromTip < buriedStart || distanceFromTip > buriedEnd) discard;
        gl_FragColor = vec4(color, 0.95);
        #include <tonemapping_fragment>
        #include <colorspace_fragment>
      }
    `,
    transparent: true, depthTest: false, depthWrite: false,
    side: THREE.DoubleSide,
  });
  const hiddenShaft = steel.clone();
  const hiddenTip = point.clone();
  for (const mesh of [hiddenShaft, hiddenTip]) {
    mesh.material = hiddenNeedle;
    mesh.layers.set(3);
    mesh.renderOrder = 20;
    mesh.castShadow = mesh.receiveShadow = false;
    mesh.visible = false;
    tool.add(mesh);
  }
  const barrel = part(tool, cylinder, material('#b2d6d7', .36, .12), [.024, .115, .024], [0, 0, -length - .092]);
  barrel.rotation.x = Math.PI / 2;
  const chamber = part(tool, sphere, material('#a8c5c5', .32, .14), [.017, .032, .020],
    [-.012, .009, -length + .074]);
  const flash = part(tool, sphere, new THREE.MeshStandardMaterial({ color: '#a42a3c', emissive: '#62101c' }),
    [.0175, .025, .0205], [-.016, .014, -length + .074]);
  chamber.rotation.x = Math.PI / 2;
  flash.rotation.x = Math.PI / 2;

  const cameraBody = new THREE.Group();
  scene.add(cameraBody);
  const mount = part(scene, cylinder, dark, [.024, 1, .024]);
  part(cameraBody, box, dark, [.093, .072, .077], [0, 0, -.054]);
  const lens = part(cameraBody, cylinder, darkGlass, [.024, .022, .024], [0, 0, -.013]);
  lens.rotation.x = Math.PI / 2;

  return (frame, camera) => {
    const [shoulder, elbow, wrist, hub, tip] = frame.arm.map(p => V(...p));
    base.position.set(shoulder.x, 0, shoulder.z);
    joints.forEach((joint, i) => joint.position.copy([shoulder, elbow, wrist][i]));
    caps.forEach((cap, i) => cap.position.copy(joints[i].position).add(V(-[.113, .099][i], 0, 0)));
    aimLink(upper, shoulder, elbow);
    const taper = elbow.clone().lerp(wrist, taperStart);
    aimLink(lower, elbow, taper);
    aimLink(neck, taper, wrist);
    aimLink(collar, wrist, hub);
    const dir = V(...frame.axis);
    const right = up.clone().cross(dir).normalize();
    const toolUp = dir.clone().cross(right).normalize();
    tool.position.copy(tip);
    tool.quaternion.setFromRotationMatrix(new THREE.Matrix4().makeBasis(right, toolUp, dir));
    const span = buriedNeedleSpan(profile, tip, hub);
    hiddenShaft.visible = hiddenTip.visible = Boolean(span && span[1] > span[0]);
    if (span) {
      hiddenNeedle.uniforms.tipWorld.value.copy(tip);
      hiddenNeedle.uniforms.axisWorld.value.copy(dir);
      hiddenNeedle.uniforms.buriedStart.value = span[0] * length;
      hiddenNeedle.uniforms.buriedEnd.value = span[1] * length;
    }
    flash.visible = frame.flash;
    chamber.visible = !frame.flash;
    const [lateral, above, along] = calibration.mount_offset_xyz;
    camera.position.copy(tip).addScaledVector(dir, along).addScaledVector(toolUp, above).addScaledVector(right, lateral);
    camera.up.copy(toolUp);
    const target = tip.clone().addScaledVector(dir, calibration.look_offset_z);
    camera.lookAt(target);
    cameraBody.position.copy(camera.position);
    cameraBody.lookAt(target);
    aimLink(mount, wrist, camera.position.clone().lerp(wrist, .19));
  };
}

export function interpolatePose(from, to, progress) {
  const mix = (a, b) => THREE.MathUtils.lerp(a, b, progress);
  const tip = V(...from.tip).lerp(V(...to.tip), progress);
  const yaw = mix(from.yaw, to.yaw);
  const pitch = mix(from.pitch, to.pitch);
  const axis = V(Math.sin(yaw) * Math.cos(pitch), Math.sin(pitch), Math.cos(yaw) * Math.cos(pitch));
  const [base, elbow, wrist, hub, startTip] = from.arm.map(point => V(...point));
  const upperLength = base.distanceTo(elbow);
  const lowerLength = elbow.distanceTo(wrist);
  const nextHub = tip.clone().addScaledVector(axis, -hub.distanceTo(startTip));
  const nextWrist = nextHub.clone().addScaledVector(axis, -wrist.distanceTo(hub));
  const reachVector = nextWrist.clone().sub(base);
  const reach = reachVector.length();
  const aim = reachVector.normalize();
  const bend = up.clone().addScaledVector(aim, -aim.y);
  if (bend.lengthSq() < 1e-16) bend.set(1, 0, 0);
  bend.normalize();
  const along = (reach ** 2 + upperLength ** 2 - lowerLength ** 2) / (2 * reach);
  const nextElbow = base.clone().addScaledVector(aim, along)
    .addScaledVector(bend, Math.sqrt(Math.max(0, upperLength ** 2 - along ** 2)));
  return {
    tip: tip.toArray(), yaw, pitch,
    axis: axis.toArray(),
    arm: [base, nextElbow, nextWrist, nextHub, tip].map(point => point.toArray()),
    flash: from.flash,
  };
}

export function setup(spec, canvas) {
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, preserveDrawingBuffer: true });
  renderer.setPixelRatio(1);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.22;
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFShadowMap;
  renderer.shadowMap.autoUpdate = false;

  const scene = new THREE.Scene();
  scene.background = new THREE.Color('#556871');
  scene.add(new THREE.HemisphereLight('#f4fcff', '#6e7d87', 2.15));
  const key = new THREE.DirectionalLight('#fff5eb', 2.1);
  key.position.set(-3.5, 7, -4);
  key.castShadow = true;
  key.shadow.mapSize.set(1536, 1536);
  Object.assign(key.shadow.camera, { left: -3, right: 3, top: 3, bottom: -3, near: 1, far: 15 });
  key.shadow.normalBias = .017;
  scene.add(key);
  const fill = new THREE.DirectionalLight('#d2eaff', .6);
  fill.position.set(3, 3, 4);
  scene.add(fill);

  table(scene, spec.elbow_z != null);
  patient(scene, spec);
  veinGeometry(scene, spec.veins);
  const calibration = spec.cameras;
  const pose = robot(scene, spec.needle_length, spec.needle_diameter ?? .017, calibration.needle, spec.robot, spec.profile);
  const contactVolume = new THREE.Mesh(new THREE.SphereGeometry(1, 24, 16),
    new THREE.MeshBasicMaterial({ color: '#ff5348', transparent: true, opacity: .38, depthTest: false }));
  const contactHalo = new THREE.Mesh(new THREE.SphereGeometry(.18, 20, 12),
    new THREE.MeshBasicMaterial({ color: '#ff5348', wireframe: true, depthTest: false }));
  const contactPoint = new THREE.Mesh(new THREE.SphereGeometry(.065, 20, 12),
    new THREE.MeshBasicMaterial({ color: '#ffef70', depthTest: false }));
  contactVolume.renderOrder = 10;
  contactHalo.renderOrder = 11;
  contactPoint.renderOrder = 12;
  for (const marker of [contactVolume, contactHalo, contactPoint]) marker.layers.set(2);
  scene.add(contactVolume, contactHalo, contactPoint);
  const { width: w, height: h, position, up: cameraUp } = calibration.overhead;
  const overhead = new THREE.OrthographicCamera(-w / 2, w / 2, h / 2, -h / 2, .1, 12);
  overhead.position.set(...position);
  overhead.up.set(...cameraUp);
  overhead.lookAt(position[0], 0, position[2]);
  const needle = new THREE.PerspectiveCamera(calibration.needle.vertical_fov_degrees, 4 / 3, .026, 14);
  const spectator = new THREE.PerspectiveCamera(38, 4 / 3, .05, 30);
  const target = V(.25, .32, spec.elbow_z == null ? -.25 : 1.25);
  spectator.position.copy(target).add(spec.elbow_z == null ? V(3.85, 3.08, -3.4) : V(6.4, 5.5, -5.0));
  spectator.lookAt(target);
  spectator.layers.enable(2);
  overhead.layers.enable(2);
  const cameras = { overhead, needle, spectator };

  function setPose(frame) {
    pose(frame, needle);
    const contact = frame.contact;
    contactVolume.visible = contactHalo.visible = contactPoint.visible = Boolean(contact);
    if (contact) {
      contactVolume.position.set(...contact.center);
      contactVolume.scale.setScalar(contact.radius);
      contactHalo.position.set(...contact.point);
      contactPoint.position.set(...contact.point);
    }
    renderer.shadowMap.needsUpdate = true;
  }
  function render(cameraName, w, h) {
    const camera = cameras[cameraName];
    if (cameraName === 'spectator') {
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    }
    renderer.setSize(w, h, false);
    renderer.render(scene, camera);
    return renderer.domElement;
  }
  function capture(frame) {
    setPose(frame);
    return Object.fromEntries(['overhead', 'needle'].map(name =>
      [name, render(name, ...calibration[name].resolution).toDataURL('image/jpeg', .96)]));
  }
  return { renderer, spectator, target, calibration, pose: setPose, render, capture };
}
