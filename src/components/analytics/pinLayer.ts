import * as maplibregl from 'maplibre-gl';
import {
  AmbientLight,
  Camera,
  CylinderGeometry,
  DirectionalLight,
  Group,
  Matrix4,
  Mesh,
  MeshLambertMaterial,
  Scene,
  SphereGeometry,
  Vector3,
  Vector4,
  WebGLRenderer,
  type Object3D,
} from 'three';
import { mixHex, toRgb } from '../../lib/colorMix';
import { EARTH_RADIUS_METRES } from '../../lib/greatCircle';

/**
 * The location pins, as real 3D geometry rather than DOM markers.
 *
 * These used to be `maplibregl.Marker`s: an SVG glyph over a pulsing halo, one
 * absolutely-positioned element per place, moved by MapLibre rewriting a
 * `transform` on every frame the camera moves. That worked, and it never looked
 * like it was standing ON the globe - a flat icon pasted over a sphere keeps
 * pointing at the screen while the planet turns underneath it.
 *
 * A pin standing in the ground turns with the ground. That is the whole reason
 * this is a custom layer: the pins are lit, they lean as the globe rotates, and
 * the ones over the horizon go behind the planet instead of floating in front
 * of it.
 *
 * **The geometry is generated, not downloaded**, and that is a decision worth
 * recording because it was made the other way twice first. A dressmaker's pin
 * is a sphere on a tapered needle - two primitives, fully described by four
 * numbers - and every downloadable model of one arrives as an approximation of
 * that: a teardrop map-marker whose head and body are one welded mesh, then a
 * thumbtack whose head is a broad dome. Each needed the head recoloured without
 * touching the needle, and each had to be reverse-engineered to find out which
 * mesh was which.
 *
 * Building it here costs about twenty lines and removes all of that: the exact
 * silhouette, an explicit head mesh and needle mesh to colour independently, no
 * asset to ship, no loader in the bundle, and no attribution to carry. What is
 * NOT lost is the thing that mattered - these are still real lit meshes in a
 * real 3D layer, standing on the globe and turning with it.
 *
 * **What replaced the ping.** The old marker pulsed a halo four times when a
 * location first appeared. Nothing here pulses: a pin is a physical object, and
 * a physical object that throbs reads as a warning rather than as a location.
 */

/**
 * The pin, in units of the head's RADIUS.
 *
 * Close to a real pin, but deliberately not a copy of one, and the difference
 * is forced by the pixel budget. A dressmaker's pin has a needle about 2.5% of
 * its length; at the ~28px this is drawn at that comes to two thirds of a
 * pixel, so the needle simply does not render and every pin is a floating bead.
 * The first attempt shipped exactly that.
 *
 * So the needle is thickened to about 6% and shortened, which keeps the
 * silhouette - ball on a spike, tapering to a point - while leaving the head
 * large enough to read a colour off and the needle wide enough to survive
 * rasterisation. Shorter also means more of the height goes to the head, which
 * is the part carrying the information.
 */
const HEAD_RADIUS = 0.7;
const NEEDLE_LENGTH = 3.6;
const NEEDLE_RADIUS = 0.2;
/** How far the needle's top is buried in the head, so no seam shows. */
const NEEDLE_INSET = 0.5;

export interface Pin {
  /** The place key this pin stands on - see placeKeyFor in GeoMap. */
  id: string;
  lngLat: [number, number];
  /** `home` is this machine's own network, and is the one pin coloured apart. */
  kind: 'host' | 'home';
}

/**
 * How tall a pin is drawn, in screen pixels.
 *
 * Screen pixels rather than metres, and that is a deliberate departure from how
 * a 3D model on a map normally works. A pin is a LABEL: it says "here", and its
 * size carries no information, so a pin that grew as you zoomed in would be
 * saying something it does not mean - and at world zoom a metre-sized pin is
 * invisible while a continent-sized one is absurd.
 *
 * The world size that produces this is recomputed per frame AND per pin, by
 * measuring the projection rather than deriving it from zoom - see the note in
 * `render`. Per pin because zoom alone is not enough in either projection: on
 * the flat map a metre covers more pixels near the poles than at the equator,
 * and on the globe apparent size depends on the camera's distance to that
 * particular pin.
 */
const PIN_PIXELS = 28;

/**
 * The needle's colour, in every pin.
 *
 * Fixed rather than themed, and that is the point of having it: the head is the
 * only part carrying information, so anything else that took a colour would be
 * competing with it.
 *
 * A MID grey, not the bright steel a real pin is. The needle is under two pixels
 * wide and it crosses both halves of the map - pale land and dark sea - so it
 * has to hold against both. A lighter grey vanished into the land entirely and
 * left the heads floating.
 */
const NEEDLE_COLOR = 0x6d7480;

/**
 * The scene's ambient intensity, named because the head colour is derived from
 * it. Raising the light without moving `gamutSafe` below puts the pins straight
 * back to where they were.
 */
export const AMBIENT_INTENSITY = 1.6;

/**
 * Pull a colour down until the ambient term alone stays inside the gamut.
 *
 * `MeshLambertMaterial` outputs roughly `base x incident`, and the ambient light
 * is 1.6 before either directional lands on it. The dark theme's accent peaks at
 * 249, so 1.6x clips that channel to 255 on EVERY part of the sphere - including
 * the side facing away from both lights. The pin ends up uniformly at full
 * intensity with no shaded side at all, which is what reads as glare against a
 * dark map.
 *
 * Scaling so the peak channel lands at `255 / AMBIENT_INTENSITY` gives the
 * unlit side the true accent hue back and lets only the lit cap clip - which is
 * a highlight, and what a lit sphere is supposed to look like.
 *
 * Derived per colour rather than as a fixed percentage: each theme's accent has
 * its own peak, and one that is already dark enough is left alone.
 */
export function gamutSafe(hex: string): string {
  const peak = Math.max(...toRgb(hex));
  const ceiling = 255 / AMBIENT_INTENSITY;
  return peak <= ceiling ? hex : mixHex(hex, '#000000', ceiling / peak);
}

/**
 * How far the pin leans, in radians.
 *
 * A pin pushed into a board by hand does not stand perfectly normal to it, and
 * one drawn that way on a globe reads as a floating icon rather than as an
 * object stuck in a surface. Leaning it also solves the view from directly
 * overhead, where a vertical pin is a dot: tilted, the head sits clear of its
 * own point at every camera angle.
 *
 * It leans back and to the left, so the head is up-screen of the tip and the
 * light in `onAdd` - which comes from the upper left - catches the head rather
 * than the shaded side.
 */
const PIN_TILT_RAD = (26 * Math.PI) / 180;

// The globe projection's unit sphere is one earth radius. See globeModelMatrix.
// The number itself lives in lib/greatCircle.ts, which is where the arc layer
// and the shader read it from too.

/**
 * How far past 90 degrees from the map centre a pin survives on the globe.
 *
 * The true horizon sits a little inside 90 degrees - `acos(R/(R+h))`, so it
 * depends on camera altitude - but the pin has height of its own and its head
 * clears the limb before its point does. Erring slightly outward keeps a pin
 * that is genuinely on the edge from popping out a frame early, which is far
 * more noticeable than one lingering a frame late.
 */
const HORIZON_COS = -0.08;

/** Pixels from the pin's head within which a pointer counts as over it. */
const HIT_RADIUS_PX = 18;

type ProjectionArgs = {
  defaultProjectionData: {
    mainMatrix: number[] | Float32Array;
    projectionTransition: number;
  };
};

/**
 * Where a pin sits on the unit sphere the globe projection works in.
 *
 * Same convention as MapLibre's own globe example: +Y is the pole, and a
 * longitude rotation about Y followed by a latitude rotation about X puts the
 * point on the +Z face.
 */
function globeUnitVector(lng: number, lat: number): Vector3 {
  const lngRad = (lng / 180) * Math.PI;
  const latRad = (lat / 180) * Math.PI;
  return new Vector3(
    Math.cos(latRad) * Math.sin(lngRad),
    Math.sin(latRad),
    Math.cos(latRad) * Math.cos(lngRad),
  );
}

/**
 * The matrix that stands a pin upright at a location on the globe.
 *
 * Lifted from MapLibre's `add-a-3d-model-to-globe-using-threejs` example, which
 * is the only authority on what space this projection actually expects - the
 * globe's unit sphere is not documented anywhere else, and getting it wrong
 * puts every pin in the Gulf of Guinea rather than failing loudly.
 *
 * The origin this places is the point on the ground. Standing the model on its
 * tip, and leaning it, are the template's job rather than this function's - see
 * the nested frames built in `onAdd`.
 */
function globeModelMatrix(lng: number, lat: number): Matrix4 {
  const scale = 1 / EARTH_RADIUS_METRES;
  return new Matrix4()
    .makeRotationY((lng / 180) * Math.PI)
    .multiply(new Matrix4().makeRotationX((-lat / 180) * Math.PI))
    .multiply(new Matrix4().makeTranslation(0, 0, 1))
    .multiply(new Matrix4().makeRotationX(Math.PI / 2))
    .multiply(new Matrix4().makeScale(scale, scale, scale));
}

/** The flat-projection equivalent. Mercator units, latitude already accounted for. */
function mercatorModelMatrix(lng: number, lat: number): Matrix4 {
  const merc = maplibregl.MercatorCoordinate.fromLngLat({ lng, lat }, 0);
  const scale = merc.meterInMercatorCoordinateUnits();
  return new Matrix4()
    .makeTranslation(merc.x, merc.y, merc.z)
    .multiply(new Matrix4().makeRotationZ(Math.PI))
    .multiply(new Matrix4().makeRotationX(Math.PI / 2))
    .multiply(new Matrix4().makeScale(-scale, scale, scale));
}

export class PinLayer implements maplibregl.CustomLayerInterface {
  readonly id = 'inwire-pins';
  readonly type = 'custom' as const;
  readonly renderingMode = '3d' as const;

  private map: maplibregl.Map | null = null;
  private renderer: WebGLRenderer | null = null;
  private scene = new Scene();
  private camera = new Camera();
  /** The loaded model, cloned per pin. Null until the GLB has arrived. */
  private template: Group | null = null;
  /** Height of the model in its own units, for standing it on its point. */
  private modelHeight = 1;
  /** The head centre in the pin's own tilted frame, for hit testing. */
  private headLocal = new Vector3();

  private pins: Pin[] = [];
  private objects = new Map<string, Object3D>();
  // Placeholders only. GeoMap calls setColors on mount with the live theme's
  // accent, which is also where the dark-theme clamp is applied - so these two
  // are deliberately NOT run through `gamutSafe`: they are what a pin is
  // painted with for the frames before the first setColors lands.
  private hostColor = '#f97316';
  private homeColor = '#38bdf8';

  /**
   * Where each pin's head landed on screen last frame, for hit testing.
   *
   * Populated during render rather than recomputed on pointer move, because the
   * matrices needed are the ones the renderer already built - and a pointer can
   * move many times between frames, so doing it here is also the cheaper half.
   */
  private screenPositions = new Map<string, { x: number; y: number }>();

  onAdd(map: maplibregl.Map, gl: WebGLRenderingContext | WebGL2RenderingContext): void {
    this.map = map;

    // Two directionals and an ambient, rather than one: the model has no
    // normals of its own (they are computed below), so a single light leaves
    // whichever side faces away completely black, and on a globe that side is
    // half the pins.
    this.scene.add(new AmbientLight(0xffffff, AMBIENT_INTENSITY));
    const key = new DirectionalLight(0xffffff, 2.2);
    key.position.set(-0.5, 1, 1).normalize();
    this.scene.add(key);
    const fill = new DirectionalLight(0xffffff, 1.1);
    fill.position.set(0.6, -0.4, -1).normalize();
    this.scene.add(fill);

    this.renderer = new WebGLRenderer({
      canvas: map.getCanvas(),
      context: gl,
      antialias: true,
    });
    // MapLibre owns the framebuffer; clearing it would erase the basemap and
    // the arcs drawn before this layer.
    this.renderer.autoClear = false;

    // The pin itself: a ball on a spike, built rather than loaded. See the note
    // at the top of this file for why.
    const head = new Mesh(
      // Enough segments that the highlight reads as a sphere at 22px and not
      // one more than that - this geometry is shared by every pin, but it is
      // still walked per pin per frame.
      new SphereGeometry(HEAD_RADIUS, 20, 14),
      new MeshLambertMaterial({ color: this.hostColor }),
    );
    head.userData.role = 'head';

    // A cone, strictly: zero radius at the bottom is what gives the needle a
    // real point rather than a flat cut end, which at this size is the
    // difference between a pin and a nail.
    const needle = new Mesh(
      new CylinderGeometry(NEEDLE_RADIUS, 0, NEEDLE_LENGTH, 8),
      new MeshLambertMaterial({ color: NEEDLE_COLOR }),
    );
    needle.userData.role = 'needle';
    // Hung from just inside the head, so the join is covered by the ball.
    needle.position.y = -NEEDLE_INSET - NEEDLE_LENGTH / 2;

    const tipDepth = NEEDLE_INSET + NEEDLE_LENGTH;
    this.modelHeight = tipDepth + HEAD_RADIUS;

    // Three nested frames, because each does one job and the layer overwrites
    // the outermost one every frame:
    //
    //   root  - its matrix is replaced per frame by `render`, and its origin is
    //           the point on the ground the pin is stuck into.
    //   tilt  - the lean, applied about the root's origin, which is the tip.
    //   lift  - raises the pin so its tip sits at that origin rather than the
    //           head's centre, which is where the geometry's own origin is.
    const lift = new Group();
    lift.position.y = tipDepth;
    lift.add(head, needle);

    const tilt = new Group();
    tilt.rotation.set(-PIN_TILT_RAD, 0, PIN_TILT_RAD * 0.45);
    tilt.add(lift);

    const root = new Group();
    root.add(tilt);

    // Where the head ends up once tilted, for the hover test. Computed once
    // rather than per frame: it only moves if the pin's proportions do.
    this.headLocal = new Vector3(0, tipDepth, 0).applyEuler(tilt.rotation);

    this.template = root;
    this.syncObjects();
  }

  onRemove(): void {
    for (const object of this.objects.values()) this.disposeObject(object);
    this.objects.clear();
    this.screenPositions.clear();
    this.renderer?.dispose();
    this.renderer = null;
    this.map = null;
  }

  /** Replaces the whole set of pins. Objects are reused where the key survives. */
  setPins(pins: Pin[]): void {
    this.pins = pins;
    this.syncObjects();
    this.map?.triggerRepaint();
  }

  /**
   * The two body colours.
   *
   * `home` differs from `host` and that is the entire signal - the pins are the
   * same object, so what tells this machine's own network apart is its colour
   * rather than a second shape nobody has seen before.
   *
   * `dim` is set on the dark themes. The clamp is applied here rather than at
   * the call site so that the caller does not have to know this scene's light
   * intensity in order to choose a colour - see `gamutSafe`.
   */
  setColors(host: string, home: string, dim: boolean): void {
    this.hostColor = dim ? gamutSafe(host) : host;
    this.homeColor = dim ? gamutSafe(home) : home;
    for (const pin of this.pins) this.paint(this.objects.get(pin.id), pin.kind);
    this.map?.triggerRepaint();
  }

  /** The pin under a point in canvas pixels, or null. Nearest head wins. */
  hitTest(x: number, y: number): Pin | null {
    let best: { pin: Pin; d2: number } | null = null;
    for (const pin of this.pins) {
      const at = this.screenPositions.get(pin.id);
      if (!at) continue;
      const d2 = (at.x - x) ** 2 + (at.y - y) ** 2;
      if (d2 > HIT_RADIUS_PX ** 2) continue;
      if (!best || d2 < best.d2) best = { pin, d2 };
    }
    return best ? best.pin : null;
  }

  render(_gl: WebGLRenderingContext | WebGL2RenderingContext, args: unknown): void {
    const map = this.map;
    const renderer = this.renderer;
    if (!map || !renderer || !this.template) return;

    const { defaultProjectionData } = args as ProjectionArgs;
    const isGlobe = defaultProjectionData.projectionTransition > 0;
    const main = new Matrix4().fromArray(Array.from(defaultProjectionData.mainMatrix));
    this.camera.projectionMatrix = main;

    /**
     * How much world one screen pixel covers, MEASURED at each pin.
     *
     * This used to be derived: `EARTH_CIRCUMFERENCE / (512 * 2^zoom)`, the
     * Web Mercator metres-per-pixel. That constant is only true at the equator,
     * and it was wrong in both projections for different reasons.
     *
     * Flat: `mercatorModelMatrix` converts metres correctly for the pin's own
     * latitude, but a metre near the poles covers MORE screen pixels than one
     * at the equator - so a pin given a fixed size in metres was drawn
     * `1 / cos(latitude)` too large. Twice the intended size at 60 degrees,
     * about four times at 75.
     *
     * Globe: world units are earth radii under a perspective camera, so
     * apparent size depends on how far the camera is from that particular pin,
     * which zoom alone cannot express. That is the one that made pins swell at
     * particular camera angles.
     *
     * Measuring sidesteps both. For each pin: take a step of a known size in
     * NDC **across** the screen, invert it back into world space, and see how
     * far it went. The step is horizontal in clip space at the pin's own depth,
     * so it is by construction perpendicular to the view direction and cannot
     * foreshorten - which is why this measures a sideways step rather than the
     * pin's own axis. Measuring the axis would collapse to zero whenever the
     * camera looked down it, which on a flat map at zero pitch is every pin.
     */
    const canvas = map.getCanvas();
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;

    const inverseMain = new Matrix4().copy(main).invert();
    /** An arbitrary NDC step. Small enough to stay local, large enough to
     *  stay well clear of floating-point noise near the far plane. */
    const NDC_STEP = 0.05;
    const stepPixels = (NDC_STEP * width) / 2;

    // The visible hemisphere, as a direction. Everything more than a right
    // angle from it is behind the planet.
    const centre = map.getCenter();
    const front = isGlobe ? globeUnitVector(centre.lng, centre.lat) : null;

    this.screenPositions.clear();

    const anchor = new Vector3();
    const clip = new Vector4();
    // Scratch vectors for the per-pin measurement above, allocated once for the
    // whole frame rather than per pin.
    const foot = new Vector3();
    const crown = new Vector3();
    const stepClip = new Vector4();
    const stepWorld = new Vector3();
    for (const pin of this.pins) {
      const object = this.objects.get(pin.id);
      if (!object) continue;

      if (front) {
        const here = globeUnitVector(pin.lngLat[0], pin.lngLat[1]);
        if (here.dot(front) < HORIZON_COS) {
          object.visible = false;
          continue;
        }
      }
      object.visible = true;

      const base = isGlobe
        ? globeModelMatrix(pin.lngLat[0], pin.lngLat[1])
        : mercatorModelMatrix(pin.lngLat[0], pin.lngLat[1]);

      // The pin's full height as a WORLD length, at scale 1. World units differ
      // per projection - earth radii on the globe, mercator units on the flat
      // map - which is exactly why this is measured off the matrix rather than
      // assumed.
      foot.set(0, 0, 0).applyMatrix4(base);
      crown.set(0, this.modelHeight, 0).applyMatrix4(base);
      const worldHeight = foot.distanceTo(crown);

      // The sideways step, at this pin's own depth. See the note above.
      clip.set(foot.x, foot.y, foot.z, 1).applyMatrix4(main);
      if (clip.w <= 0 || worldHeight <= 0) {
        object.visible = false;
        continue;
      }
      stepClip
        .set(clip.x + NDC_STEP * clip.w, clip.y, clip.z, clip.w)
        .applyMatrix4(inverseMain);
      stepWorld.set(stepClip.x / stepClip.w, stepClip.y / stepClip.w, stepClip.z / stepClip.w);
      const worldPerPixel = foot.distanceTo(stepWorld) / stepPixels;

      const modelScale = (PIN_PIXELS * worldPerPixel) / worldHeight;
      if (!Number.isFinite(modelScale) || modelScale <= 0) {
        object.visible = false;
        continue;
      }

      // Only the scale. Standing the pin on its tip and leaning it are baked
      // into the template's own nested frames, so they survive this matrix
      // being rewritten from scratch every frame.
      base.multiply(new Matrix4().makeScale(modelScale, modelScale, modelScale));

      object.matrixAutoUpdate = false;
      object.matrix.copy(base);

      // Where the head ends up on screen, for the hover test. The head rather
      // than the tip, because the head is what a pointer is aimed at - and once
      // the pin leans, the two are not the same place.
      anchor.copy(this.headLocal).applyMatrix4(base);
      clip.set(anchor.x, anchor.y, anchor.z, 1).applyMatrix4(main);
      // A w at or below zero is a point behind the camera. Dividing by it would
      // mirror the pin onto the opposite side of the screen and leave a hit
      // target sitting where nothing is drawn.
      if (clip.w > 0) {
        this.screenPositions.set(pin.id, {
          x: ((clip.x / clip.w + 1) / 2) * width,
          y: ((1 - clip.y / clip.w) / 2) * height,
        });
      }
    }

    // MapLibre and three.js each believe they own the GL state machine, so it
    // has to be handed back deliberately in both directions.
    renderer.resetState();
    renderer.render(this.scene, this.camera);
  }

  /** Builds or drops pin objects so the scene matches `pins`. */
  private syncObjects(): void {
    if (!this.template) return;
    const wanted = new Set(this.pins.map((p) => p.id));

    for (const [id, object] of this.objects) {
      if (wanted.has(id)) continue;
      this.scene.remove(object);
      this.disposeObject(object);
      this.objects.delete(id);
    }

    for (const pin of this.pins) {
      if (this.objects.has(pin.id)) continue;
      // `clone` shares geometry between instances and copies the material
      // references, so `paint` below has to replace them per instance or every
      // pin would take the last colour written.
      const object = this.template.clone(true);
      this.paint(object, pin.kind);
      this.scene.add(object);
      this.objects.set(pin.id, object);
    }
  }

  /**
   * Colours one pin's head, and only its head.
   *
   * The needle keeps the grey it was built with. That split is the entire
   * reason head and needle are separate meshes: colour here is carrying one
   * piece of information - whether this place is yours - and a pin whose spike
   * changed colour too would be saying it twice, louder, in the part of the
   * shape that is mostly a line.
   */
  private paint(object: Object3D | undefined, kind: Pin['kind']): void {
    if (!object) return;
    const isHome = kind === 'home';
    const color = isHome ? this.homeColor : this.hostColor;
    // Your own pin is never allowed to end up behind somebody else's, and this
    // is not a hypothetical tidy-up: the address your traffic leaves through
    // and the servers you talk to are often in the same city, so the home pin
    // and a host pin land on the same pixel. Measured on a real capture, the
    // two sat 0.4px apart and the host won the depth test - so the one pin that
    // is coloured differently was the one you could not see.
    //
    // Drawn last and without a depth test, so it wins regardless. Safe because
    // pins past the limb are culled outright (see HORIZON_COS) rather than
    // relying on the depth buffer to hide them.
    object.renderOrder = isHome ? 1 : 0;
    object.traverse((child) => {
      const mesh = child as Mesh;
      if (!mesh.isMesh) return;
      const role = mesh.userData.role;
      if (role !== 'head' && !isHome) return;
      // A fresh material per instance, so two pins of different kinds cannot
      // end up sharing one - which also means the home pin's depthTest flag
      // cannot leak onto every other pin through a shared needle material.
      mesh.material = new MeshLambertMaterial({
        color: role === 'head' ? color : NEEDLE_COLOR,
        depthTest: !isHome,
      });
    });
  }

  private disposeObject(object: Object3D): void {
    object.traverse((child) => {
      const mesh = child as Mesh;
      if (!mesh.isMesh) return;
      const material = mesh.material;
      if (Array.isArray(material)) material.forEach((m) => m.dispose());
      else material?.dispose();
    });
  }
}
