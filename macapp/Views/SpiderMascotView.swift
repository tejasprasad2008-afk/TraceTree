import SwiftUI
import SceneKit

// MARK: - Spider Mascot (SceneKit, fully procedural)

struct SpiderMascotView: NSViewRepresentable {
    var verdict: Verdict
    var isScanning: Bool

    func makeNSView(context: Context) -> SCNView {
        let view = SCNView(frame: .zero)
        view.scene = SpiderScene.build()
        view.allowsCameraControl = false
        view.backgroundColor = .clear
        view.isJitteringEnabled = true
        view.antialiasingMode = .multisampling4X
        return view
    }

    func updateNSView(_ view: SCNView, context: Context) {
        guard let scene = view.scene else { return }
        SpiderScene.updateGlow(scene: scene, verdict: verdict, isScanning: isScanning)
    }
}

// MARK: - Scene builder

private enum SpiderScene {

    static let glowLightName = "glow_light"
    static let legRootPrefix = "leg_root_"
    static let eyePrefix     = "eye_"

    static func build() -> SCNScene {
        let scene = SCNScene()

        // Camera
        let camNode = SCNNode()
        camNode.camera = SCNCamera()
        camNode.position = SCNVector3(0, 0.3, 2.2)
        camNode.look(at: SCNVector3(0, 0, 0))
        scene.rootNode.addChildNode(camNode)

        // Ambient light
        let ambient = SCNNode()
        ambient.light = SCNLight()
        ambient.light?.type = .ambient
        ambient.light?.color = NSColor(red: 0.05, green: 0.05, blue: 0.1, alpha: 1)
        scene.rootNode.addChildNode(ambient)

        // Spot light from above
        let spot = SCNNode()
        spot.light = SCNLight()
        spot.light?.type = .spot
        spot.light?.color = NSColor(white: 0.7, alpha: 1)
        spot.light?.spotInnerAngle = 30
        spot.light?.spotOuterAngle = 60
        spot.position = SCNVector3(0, 3, 2)
        spot.look(at: SCNVector3(0, 0, 0))
        scene.rootNode.addChildNode(spot)

        // Verdict-driven glow omni
        let glow = SCNNode()
        glow.name = glowLightName
        glow.light = SCNLight()
        glow.light?.type = .omni
        glow.light?.color = NSColor.orange
        glow.light?.intensity = 300
        glow.position = SCNVector3(0, 0.5, 0.8)
        scene.rootNode.addChildNode(glow)

        // Spider root — idle bob lives here
        let spiderRoot = SCNNode()
        spiderRoot.name = "spider_root"
        scene.rootNode.addChildNode(spiderRoot)
        addIdleBob(to: spiderRoot)

        // Abdomen
        let abdomen = makeBody(radius: 0.28,
                               color: NSColor(red: 0.08, green: 0.08, blue: 0.08, alpha: 1),
                               specular: NSColor(red: 0.3, green: 0.1, blue: 0.5, alpha: 1))
        abdomen.position = SCNVector3(0, 0, 0.15)
        spiderRoot.addChildNode(abdomen)

        // Red hourglass marking
        let marking = makeBody(radius: 0.08,
                               color: NSColor(red: 0.9, green: 0.1, blue: 0.0, alpha: 1),
                               specular: .red)
        marking.geometry?.firstMaterial?.emission.contents = NSColor(red: 0.9, green: 0.05, blue: 0.0, alpha: 1)
        marking.position = SCNVector3(0, -0.05, 0.18)
        abdomen.addChildNode(marking)

        // Cephalothorax
        let cephalo = makeBody(radius: 0.20,
                               color: NSColor(red: 0.10, green: 0.10, blue: 0.12, alpha: 1),
                               specular: NSColor(red: 0.2, green: 0.2, blue: 0.4, alpha: 1))
        cephalo.position = SCNVector3(0, 0, -0.25)
        spiderRoot.addChildNode(cephalo)

        // Pedicel (waist connector)
        let pedicel = SCNNode(geometry: SCNCylinder(radius: 0.05, height: 0.12))
        pedicel.geometry?.firstMaterial?.diffuse.contents = NSColor(red: 0.08, green: 0.08, blue: 0.1, alpha: 1)
        pedicel.eulerAngles.x = .pi / 2
        pedicel.position = SCNVector3(0, 0, 0.01)
        spiderRoot.addChildNode(pedicel)

        // 8 eyes (4 pairs)
        let eyeXY: [(Float, Float)] = [
            (-0.07, 0.09), (0.07, 0.09),
            (-0.11, 0.04), (0.11, 0.04),
            (-0.09, -0.02), (0.09, -0.02),
            (-0.05,  0.00), (0.05,  0.00),
        ]
        for (i, pos) in eyeXY.enumerated() {
            let eye = SCNNode(geometry: SCNSphere(radius: 0.025))
            eye.name = "\(eyePrefix)\(i)"
            eye.geometry?.firstMaterial?.diffuse.contents  = NSColor(red: 0.9, green: 0.3, blue: 0.0, alpha: 1)
            eye.geometry?.firstMaterial?.emission.contents = NSColor(red: 1.0, green: 0.4, blue: 0.0, alpha: 1)
            eye.geometry?.firstMaterial?.shininess = 1.0
            eye.position = SCNVector3(pos.0, pos.1, -0.42)
            spiderRoot.addChildNode(eye)
        }

        // Fangs
        for side: Float in [-1, 1] {
            let fang = SCNNode(geometry: SCNCone(topRadius: 0.005, bottomRadius: 0.015, height: 0.08))
            fang.geometry?.firstMaterial?.diffuse.contents = NSColor(red: 0.3, green: 0.1, blue: 0.1, alpha: 1)
            fang.eulerAngles.x = .pi / 2 + 0.3
            fang.position = SCNVector3(side * 0.05, -0.1, -0.45)
            spiderRoot.addChildNode(fang)
        }

        // 8 legs: (side, zOffset, alternating phase, spread degrees)
        let legCfgs: [(side: Float, z: Float, phase: Double, spread: Float)] = [
            (-1, -0.30, 0.0, 35), (-1, -0.15, 0.5, 40),
            (-1,  0.00, 0.0, 42), (-1,  0.15, 0.5, 38),
            ( 1, -0.30, 0.5, 35), ( 1, -0.15, 0.0, 40),
            ( 1,  0.00, 0.5, 42), ( 1,  0.15, 0.0, 38),
        ]
        for (i, cfg) in legCfgs.enumerated() {
            let legRoot = SCNNode()
            legRoot.name = "\(legRootPrefix)\(i)"
            legRoot.position = SCNVector3(cfg.side * 0.15, -0.02, cfg.z)
            spiderRoot.addChildNode(legRoot)
            buildLeg(on: legRoot, side: cfg.side, spread: cfg.spread)
            animateLeg(legRoot, phase: cfg.phase, duration: 0.7)
        }

        return scene
    }

    // MARK: - Geometry

    private static func makeBody(radius: Double, color: NSColor, specular: NSColor) -> SCNNode {
        let s = SCNSphere(radius: radius)
        s.segmentCount = 32
        s.firstMaterial?.diffuse.contents  = color
        s.firstMaterial?.specular.contents = specular
        s.firstMaterial?.shininess         = 80
        s.firstMaterial?.metalness.intensity  = 0.7
        s.firstMaterial?.roughness.intensity  = 0.2
        return SCNNode(geometry: s)
    }

    private static func buildLeg(on root: SCNNode, side: Float, spread: Float) {
        let rad = spread * Float.pi / 180
        let fLen: CGFloat = 0.28
        let tLen: CGFloat = 0.32

        // Femur
        let femur = SCNNode(geometry: SCNCylinder(radius: 0.018, height: fLen))
        applyLegMat(femur)
        femur.eulerAngles = SCNVector3(0, 0, side * (.pi / 2 + rad * 0.3))
        femur.position = SCNVector3(side * Float(fLen / 2) * cos(rad), 0, 0)
        root.addChildNode(femur)

        // Knee
        let knee = SCNNode()
        knee.position = SCNVector3(side * Float(fLen) * cos(rad), -Float(fLen) * 0.3, 0)
        root.addChildNode(knee)

        // Tibia
        let tibia = SCNNode(geometry: SCNCylinder(radius: 0.012, height: tLen))
        applyLegMat(tibia)
        tibia.eulerAngles = SCNVector3(0, 0, side * (.pi / 2 + rad * 0.6))
        tibia.position = SCNVector3(side * Float(tLen / 2) * cos(rad * 1.3), -Float(tLen / 2) * 0.5, 0)
        knee.addChildNode(tibia)

        // Foot dot
        let foot = SCNNode(geometry: SCNSphere(radius: 0.016))
        foot.geometry?.firstMaterial?.diffuse.contents = NSColor(red: 0.15, green: 0.05, blue: 0.05, alpha: 1)
        foot.position = SCNVector3(side * Float(tLen) * cos(rad * 1.3), -Float(tLen) * 0.5, 0)
        knee.addChildNode(foot)
    }

    private static func applyLegMat(_ node: SCNNode) {
        node.geometry?.firstMaterial?.diffuse.contents  = NSColor(red: 0.12, green: 0.10, blue: 0.14, alpha: 1)
        node.geometry?.firstMaterial?.specular.contents = NSColor(red: 0.25, green: 0.15, blue: 0.35, alpha: 1)
        node.geometry?.firstMaterial?.shininess         = 60
    }

    // MARK: - Animations

    private static func addIdleBob(to node: SCNNode) {
        let bob = CABasicAnimation(keyPath: "position.y")
        bob.fromValue    = -0.03
        bob.toValue      =  0.03
        bob.duration     = 2.2
        bob.autoreverses = true
        bob.repeatCount  = .infinity
        bob.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        node.addAnimation(bob, forKey: "bob")

        let sway = CABasicAnimation(keyPath: "eulerAngles.z")
        sway.fromValue    = -0.04
        sway.toValue      =  0.04
        sway.duration     = 3.1
        sway.autoreverses = true
        sway.repeatCount  = .infinity
        sway.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        node.addAnimation(sway, forKey: "sway")
    }

    private static func animateLeg(_ node: SCNNode, phase: Double, duration: Double) {
        let lift = CABasicAnimation(keyPath: "eulerAngles.x")
        lift.fromValue    = -0.18
        lift.toValue      =  0.18
        lift.duration     = duration
        lift.autoreverses = true
        lift.repeatCount  = .infinity
        lift.timeOffset   = phase * duration
        lift.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        node.addAnimation(lift, forKey: "lift")

        let swing = CABasicAnimation(keyPath: "eulerAngles.y")
        swing.fromValue    = -0.12
        swing.toValue      =  0.12
        swing.duration     = duration
        swing.autoreverses = true
        swing.repeatCount  = .infinity
        swing.timeOffset   = phase * duration + duration * 0.5
        swing.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        node.addAnimation(swing, forKey: "swing")
    }

    // MARK: - Verdict-driven glow update

    static func updateGlow(scene: SCNScene, verdict: Verdict, isScanning: Bool) {
        guard let glow      = scene.rootNode.childNode(withName: glowLightName,   recursively: false),
              let spiderRoot = scene.rootNode.childNode(withName: "spider_root",  recursively: false)
        else { return }

        let glowColor:     NSColor
        let glowIntensity: CGFloat
        let bobSpeed:      Double
        let legDuration:   Double
        let eyeEmission:   NSColor

        switch verdict {
        case .malicious:
            glowColor = NSColor(red: 1, green: 0.04, blue: 0.04, alpha: 1); glowIntensity = 900
            bobSpeed = 0.38; legDuration = 0.20
            eyeEmission = NSColor(red: 1, green: 0, blue: 0, alpha: 1)
        case .suspicious:
            glowColor = NSColor(red: 1, green: 0.55, blue: 0, alpha: 1); glowIntensity = 550
            bobSpeed = 0.9; legDuration = 0.45
            eyeEmission = NSColor(red: 1, green: 0.5, blue: 0, alpha: 1)
        case .clean:
            glowColor = NSColor(red: 0.1, green: 1, blue: 0.3, alpha: 1); glowIntensity = 380
            bobSpeed = 2.2; legDuration = 0.8
            eyeEmission = NSColor(red: 0.1, green: 1, blue: 0.2, alpha: 1)
        case .unknown:
            let scanning = isScanning
            glowColor = NSColor(red: 0.4, green: 0.2, blue: 0.9, alpha: 1)
            glowIntensity = scanning ? 600 : 280
            bobSpeed = scanning ? 0.38 : 2.2; legDuration = scanning ? 0.25 : 0.7
            eyeEmission = NSColor(red: 0.9, green: 0.3, blue: 0, alpha: 1)
        }

        SCNTransaction.begin()
        SCNTransaction.animationDuration = 0.6
        glow.light?.color     = glowColor
        glow.light?.intensity = glowIntensity
        SCNTransaction.commit()

        // Eye glow
        scene.rootNode.enumerateChildNodes { node, _ in
            guard let name = node.name, name.hasPrefix(eyePrefix) else { return }
            SCNTransaction.begin()
            SCNTransaction.animationDuration = 0.6
            node.geometry?.firstMaterial?.emission.contents = eyeEmission
            node.geometry?.firstMaterial?.diffuse.contents  = eyeEmission
            SCNTransaction.commit()
        }

        // Bob speed
        let bob = CABasicAnimation(keyPath: "position.y")
        bob.fromValue = -0.04; bob.toValue = 0.04
        bob.duration = bobSpeed; bob.autoreverses = true; bob.repeatCount = .infinity
        bob.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        spiderRoot.addAnimation(bob, forKey: "bob")

        // Leg speed
        scene.rootNode.enumerateChildNodes { node, _ in
            guard let name = node.name, name.hasPrefix(legRootPrefix) else { return }
            let idx = Double(name.split(separator: "_").last.flatMap { Int($0) } ?? 0)
            let phase = (idx.truncatingRemainder(dividingBy: 2)) * 0.5
            animateLeg(node, phase: phase, duration: legDuration)
        }
    }
}
