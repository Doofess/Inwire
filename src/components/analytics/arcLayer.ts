import type { CustomLayerInterface, CustomRenderMethodInput, Map as MapLibreMap } from 'maplibre-gl';
import type { LngLatAlt } from '../../lib/greatCircle';

/**
 * One route, as a polyline with altitude and a colour.
 *
 * Altitude arrives as a fraction of the globe's radius (see `greatCircleArc`)
 * and is converted to metres here, because metres is what MapLibre's globe
 * shader means by "elevation".
 */
export interface Arc {
  points: LngLatAlt[];
  /** `#rrggbb`. */
  color: string;
  /** 0..1, scaled into a line width. */
  weight: number;
}

/**
 * Connection arcs that leave the surface, drawn in raw WebGL.
 *
 * MapLibre cannot do this with a style layer. Its line layer has no altitude of
 * any kind - there is no `line-z-offset` and no elevation reference anywhere in
 * 6.5.0 - so a line is painted flat on the ground and that is the end of it. A
 * route that lifts off the planet has to be drawn by hand.
 *
 * ## Projection
 *
 * The hard part is not the arc, it is agreeing with MapLibre about where things
 * are. A custom layer is handed matrices and left to project for itself, and a
 * layer that projects even slightly differently from the basemap slides against
 * it as the camera moves - which is worse than not drawing at all, because it
 * looks like the data is wrong rather than the renderer.
 *
 * So the shader below does not approximate MapLibre's projection; it
 * reimplements it, function for function, from the formulas MapLibre's own
 * shaders use:
 *
 *   - `projectToSphere` - mercator 0..1 to a point on the unit sphere, latitude
 *     via the inverse Gudermannian. The axis convention is MapLibre's: Y is the
 *     polar axis, X and Z span the equatorial plane.
 *   - radial elevation - `spherePos * (1 + elevation / GLOBE_RADIUS)`, which is
 *     how MapLibre elevates terrain and exactly what an arc needs.
 *   - `globeComputeClippingZ` - the horizon plane written into clip Z, so
 *     geometry on the far side of the planet is clipped rather than drawn
 *     through it. MapLibre never renders the globe into the depth buffer, so
 *     without this an arc behind the Earth draws in front of it.
 *   - the mercator fallback blend - globe falls back to a flat projection as
 *     zoom increases, and `u_projection_transition` drives the crossfade.
 *     Ignoring it is what makes a custom layer visibly detach from the map
 *     halfway through a zoom.
 *
 * ## Thickness
 *
 * `gl.LINES` is capped at one pixel on essentially every platform, so lines are
 * built from triangles: each point is emitted twice, offset perpendicular to
 * its segment in SCREEN space, so a route keeps its width however the sphere
 * turns underneath it.
 */
const GLOBE_RADIUS_METRES = 6371008.8;

/** Floats per vertex - see ATTRIBUTES for the layout. */
const STRIDE = 12;

const VERTEX_SRC = `
precision highp float;

attribute vec2  a_merc;
attribute float a_elev;
attribute vec2  a_other;
attribute float a_otherElev;
attribute float a_side;
attribute float a_flip;
attribute vec3  a_color;
attribute float a_width;

uniform mat4  u_matrix;
uniform mat4  u_fallback;
uniform vec4  u_clip;
uniform float u_transition;
uniform vec2  u_halfViewport;
uniform float u_widthScale;
uniform vec4  u_tileMercatorCoords;

varying vec3 v_color;

const float PI_ = 3.14159265359;

vec3 projectToSphere(vec2 merc) {
  float sx = merc.x * PI_ * 2.0 + PI_;
  float t = exp(PI_ - (merc.y * PI_ * 2.0));
  float t2 = t * t;
  float denom = t2 + 1.0;
  float sinLat = (t2 - 1.0) / denom;
  float cosLat = (2.0 * t) / denom;
  return vec3(sin(sx) * cosLat, sinLat, cos(sx) * cosLat);
}

vec4 project(vec2 merc, float elev) {
  vec3 sphere = projectToSphere(merc);
  vec3 elevated = sphere * (1.0 + elev / 6371008.8);
  vec4 globePos = u_matrix * vec4(elevated, 1.0);
  globePos.z = (1.0 - (dot(elevated, u_clip.xyz) + u_clip.w)) * globePos.w;
  if (u_transition > 0.999) return globePos;

  // The flat matrix consumes IN-TILE coordinates, not mercator ones. MapLibre
  // relates the two as
  //     mercator = u_tileMercatorCoords.xy + u_tileMercatorCoords.zw * inTile
  // so this inverts it rather than hardcoding the 0..8192 tile extent, which
  // would be a magic number tied to a value MapLibre is free to change.
  //
  // Getting this wrong is silent: the flat path drew its arcs 8192x too close
  // to the origin, which is to say a fraction of a pixel wide in the top-left
  // corner, and the map simply looked as though it had no connections at all.
  vec2 inTile = (merc - u_tileMercatorCoords.xy) / max(u_tileMercatorCoords.zw, vec2(1e-9));
  vec4 flatPos = u_fallback * vec4(inTile, elev, 1.0);
  vec4 result = globePos;
  float zBlend = clamp((u_transition - 0.2) / 0.8, 0.0, 1.0);
  result.z = mix(0.0, globePos.z, zBlend);
  result.xyw = mix(flatPos.xyw, globePos.xyw, u_transition);
  return result;
}

void main() {
  vec4 self = project(a_merc, a_elev);
  vec4 other = project(a_other, a_otherElev);

  vec2 selfPx = (self.xy / self.w) * u_halfViewport;
  vec2 otherPx = (other.xy / other.w) * u_halfViewport;

  vec2 delta = (otherPx - selfPx) * a_flip;
  vec2 dir = length(delta) < 0.0001 ? vec2(1.0, 0.0) : normalize(delta);
  vec2 normal = vec2(-dir.y, dir.x);

  vec2 offsetPx = normal * a_side * a_width * u_widthScale * 0.5;
  vec2 ndc = (selfPx + offsetPx) / u_halfViewport;

  gl_Position = vec4(ndc * self.w, self.z, self.w);
  v_color = a_color;
}
`;

const FRAGMENT_SRC = `
precision mediump float;
varying vec3 v_color;
uniform float u_opacity;
void main() {
  gl_FragColor = vec4(v_color * u_opacity, u_opacity);
}
`;

const ATTRIBUTES: Array<[name: string, size: number]> = [
  ['a_merc', 2],
  ['a_elev', 1],
  ['a_other', 2],
  ['a_otherElev', 1],
  ['a_side', 1],
  ['a_flip', 1],
  ['a_color', 3],
  ['a_width', 1],
];

const UNIFORMS = [
  'u_matrix',
  'u_fallback',
  'u_clip',
  'u_transition',
  'u_halfViewport',
  'u_opacity',
  'u_widthScale',
  'u_tileMercatorCoords',
];

function compile(gl: WebGLRenderingContext, type: number, source: string): WebGLShader {
  const shader = gl.createShader(type);
  if (!shader) throw new Error('could not create arc shader');
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    const log = gl.getShaderInfoLog(shader);
    gl.deleteShader(shader);
    throw new Error('arc shader failed to compile: ' + log);
  }
  return shader;
}

/** `#rrggbb` to 0..1 components. Falls back to white rather than throwing. */
export function rgbComponents(hex: string): [number, number, number] {
  const match = /^#?([0-9a-f]{6})$/i.exec(hex.trim());
  if (!match) return [1, 1, 1];
  const n = parseInt(match[1], 16);
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}

/**
 * Web Mercator, normalised to 0..1 - the space MapLibre's shaders work in.
 *
 * Exported so the assertion script can check it against MapLibre's own
 * MercatorCoordinate without needing a GL context.
 */
export function toMercator(lng: number, lat: number): [number, number] {
  const x = (180 + lng) / 360;
  // Clamped short of the poles, where the projection runs to infinity.
  const clamped = Math.max(-85.051129, Math.min(85.051129, lat));
  const s = Math.sin((clamped * Math.PI) / 180);
  const y = 0.5 - Math.log((1 + s) / (1 - s)) / (4 * Math.PI);
  return [x, y];
}

export class ArcLayer implements CustomLayerInterface {
  readonly id = 'netview-arcs';
  readonly type = 'custom' as const;
  readonly renderingMode = '3d' as const;

  private map: MapLibreMap | null = null;
  private program: WebGLProgram | null = null;
  private buffer: WebGLBuffer | null = null;
  private locations: Record<string, number> = {};
  private uniforms: Record<string, WebGLUniformLocation | null> = {};

  private vertices = new Float32Array(0);
  private vertexCount = 0;
  private dirty = false;

  /** Kept so the buffer can be rebuilt when the layer is re-added. */
  private arcs: Arc[] = [];

  onAdd(map: MapLibreMap, gl: WebGLRenderingContext): void {
    this.map = map;

    const program = gl.createProgram();
    if (!program) throw new Error('could not create arc program');
    const vertex = compile(gl, gl.VERTEX_SHADER, VERTEX_SRC);
    const fragment = compile(gl, gl.FRAGMENT_SHADER, FRAGMENT_SRC);
    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.linkProgram(program);
    // Flagged now; the program keeps them alive until it is itself deleted.
    gl.deleteShader(vertex);
    gl.deleteShader(fragment);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      throw new Error('arc program failed to link: ' + gl.getProgramInfoLog(program));
    }

    this.program = program;
    for (const [name] of ATTRIBUTES) this.locations[name] = gl.getAttribLocation(program, name);
    for (const name of UNIFORMS) this.uniforms[name] = gl.getUniformLocation(program, name);

    this.buffer = gl.createBuffer();
    // The layer can be re-added to a rebuilt style with arcs already set.
    this.build();
    this.dirty = true;
  }

  onRemove(_map: MapLibreMap, gl: WebGLRenderingContext): void {
    if (this.program) gl.deleteProgram(this.program);
    if (this.buffer) gl.deleteBuffer(this.buffer);
    this.program = null;
    this.buffer = null;
    this.map = null;
  }

  /**
   * Replaces the geometry.
   *
   * Driven by the map's existing throttle rather than by each packet: building
   * and uploading the buffer is real work, and the routes change on every frame
   * of a busy capture.
   */
  setArcs(arcs: Arc[]): void {
    this.arcs = arcs;
    this.build();
    this.dirty = true;
    this.map?.triggerRepaint();
  }

  private build(): void {
    let segments = 0;
    for (const arc of this.arcs) segments += Math.max(0, arc.points.length - 1);

    const data = new Float32Array(segments * 6 * STRIDE);
    let at = 0;

    const push = (
      merc: [number, number],
      elev: number,
      other: [number, number],
      otherElev: number,
      side: number,
      flip: number,
      color: [number, number, number],
      width: number,
    ) => {
      data[at++] = merc[0];
      data[at++] = merc[1];
      data[at++] = elev;
      data[at++] = other[0];
      data[at++] = other[1];
      data[at++] = otherElev;
      data[at++] = side;
      data[at++] = flip;
      data[at++] = color[0];
      data[at++] = color[1];
      data[at++] = color[2];
      data[at++] = width;
    };

    for (const arc of this.arcs) {
      const color = rgbComponents(arc.color);
      // The same ramp the line layer used, so a busy route still draws heavier.
      const width = 0.8 + Math.max(0, Math.min(1, arc.weight)) * 1.8;

      for (let i = 0; i < arc.points.length - 1; i++) {
        const a = arc.points[i];
        const b = arc.points[i + 1];
        const ma = toMercator(a[0], a[1]);
        const mb = toMercator(b[0], b[1]);
        const ea = a[2] * GLOBE_RADIUS_METRES;
        const eb = b[2] * GLOBE_RADIUS_METRES;

        // `flip` is +1 at the segment's start and -1 at its end, so both ends
        // compute the same direction and the quad cannot twist.
        push(ma, ea, mb, eb, -1, 1, color, width);
        push(ma, ea, mb, eb, 1, 1, color, width);
        push(mb, eb, ma, ea, -1, -1, color, width);

        push(mb, eb, ma, ea, -1, -1, color, width);
        push(ma, ea, mb, eb, 1, 1, color, width);
        push(mb, eb, ma, ea, 1, -1, color, width);
      }
    }

    this.vertices = data;
    this.vertexCount = segments * 6;
  }

  render(gl: WebGLRenderingContext, args: CustomRenderMethodInput): void {
    if (!this.program || !this.buffer || this.vertexCount === 0) return;

    // Both projections need a REAL tile id, and only globe wants the globe
    // matrix.
    //
    // The typings declare `tileID: UnwrappedTileIDLiteral | null`, so null
    // reads as "no particular tile, just the world". Nothing accepts it:
    // MapLibre dereferences `tileID.canonical` unguarded and throws
    // "Cannot read properties of null (reading 'canonical')" on every frame,
    // 60 times a second, in both projections. The zoom-0 tile is the honest
    // request anyway, since it covers the whole world and no arc can fall
    // outside it.
    //
    // `applyGlobeMatrix` is the part that must differ: asking for the globe
    // matrix while the map is flat sends the request down a globe-only path
    // with no globe to read.
    const isGlobe = this.map?.getProjection().type === 'globe';
    let projection;
    try {
      projection = args.getProjectionData({
        tileID: { wrap: 0, canonical: { x: 0, y: 0, z: 0 } },
        applyGlobeMatrix: isGlobe,
      });
    } catch {
      // Never let a projection failure become a per-frame exception storm.
      // Skipping a frame is invisible; filling the console is not.
      return;
    }

    // `fallbackMatrix` is the flat projection in BOTH modes: under globe it is
    // the mercator projection the globe crossfades into at high zoom, and under
    // mercator it is byte-identical to `mainMatrix`. Verified by reading both
    // back at runtime rather than assumed.
    const flatMatrix = projection.fallbackMatrix as Float32Array;

    gl.useProgram(this.program);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.buffer);
    if (this.dirty) {
      gl.bufferData(gl.ARRAY_BUFFER, this.vertices, gl.DYNAMIC_DRAW);
      this.dirty = false;
    }

    const bytes = STRIDE * 4;
    let offset = 0;
    for (const [name, size] of ATTRIBUTES) {
      const location = this.locations[name];
      if (location >= 0) {
        gl.enableVertexAttribArray(location);
        gl.vertexAttribPointer(location, size, gl.FLOAT, false, bytes, offset);
      }
      offset += size * 4;
    }

    gl.uniformMatrix4fv(this.uniforms.u_matrix, false, projection.mainMatrix as Float32Array);
    gl.uniformMatrix4fv(this.uniforms.u_fallback, false, flatMatrix);
    gl.uniform4fv(this.uniforms.u_clip, projection.clippingPlane);
    gl.uniform1f(this.uniforms.u_transition, projection.projectionTransition);
    gl.uniform4fv(this.uniforms.u_tileMercatorCoords, projection.tileMercatorCoords);
    gl.uniform2f(
      this.uniforms.u_halfViewport,
      gl.drawingBufferWidth / 2,
      gl.drawingBufferHeight / 2,
    );

    gl.enable(gl.BLEND);
    // Premultiplied alpha: the fragment shader already multiplies, which is
    // what lets the glow pass add light without darkening the map beneath it.
    gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
    gl.disable(gl.CULL_FACE);

    // Two passes over the same geometry: a wide faint one that reads as glow,
    // then the line itself. This is what the line layer got from `line-blur`,
    // which has no equivalent here.
    gl.uniform1f(this.uniforms.u_widthScale, 3.5);
    gl.uniform1f(this.uniforms.u_opacity, 0.16);
    gl.drawArrays(gl.TRIANGLES, 0, this.vertexCount);

    gl.uniform1f(this.uniforms.u_widthScale, 1);
    gl.uniform1f(this.uniforms.u_opacity, 0.85);
    gl.drawArrays(gl.TRIANGLES, 0, this.vertexCount);

    // Hand the context back as it was found.
    //
    // A custom layer shares one GL context with the whole renderer, and
    // MapLibre draws everything after this with whatever state is left behind.
    // Vertex attribute arrays are the dangerous part: an array still enabled
    // for an attribute the NEXT program does not declare is read anyway, from
    // this layer's buffer, at this layer's stride - which is how a custom layer
    // makes the basemap flicker and tear rather than merely drawing itself
    // wrong. Cheap insurance, and invisible when it is working.
    for (const [name] of ATTRIBUTES) {
      const location = this.locations[name];
      if (location >= 0) gl.disableVertexAttribArray(location);
    }
    gl.bindBuffer(gl.ARRAY_BUFFER, null);
  }
}
