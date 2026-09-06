import UIKit

// Programmatic base for all module VCs.
// viewDidLoad sequence: setupScrollStack → buildContent (subclass adds buttons/fields)
//                       → appendOutputLabel (last in stack so output is always at bottom)
class VulnBaseViewController: UIViewController {

    var outputLabel: UILabel!
    private var contentStack: UIStackView!

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        setupScrollStack()
        buildContent()
        appendOutputLabel()
    }

    func buildContent() {}

    private func setupScrollStack() {
        let scroll = UIScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scroll)

        let stack = UIStackView()
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        scroll.addSubview(stack)
        contentStack = stack

        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            stack.topAnchor.constraint(equalTo: scroll.topAnchor, constant: 16),
            stack.leadingAnchor.constraint(equalTo: scroll.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: scroll.trailingAnchor, constant: -16),
            stack.bottomAnchor.constraint(equalTo: scroll.bottomAnchor, constant: -16),
            stack.widthAnchor.constraint(equalTo: scroll.widthAnchor, constant: -32),
        ])
    }

    private func appendOutputLabel() {
        let label = UILabel()
        label.numberOfLines = 0
        label.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        label.textColor = .label
        contentStack.addArrangedSubview(label)
        outputLabel = label
    }

    func addLabel(_ text: String) {
        let label = UILabel()
        label.text = text
        label.numberOfLines = 0
        label.font = .systemFont(ofSize: 13)
        label.textColor = .secondaryLabel
        contentStack.addArrangedSubview(label)
    }

    @discardableResult
    func addExtraLabel() -> UILabel {
        let label = UILabel()
        label.numberOfLines = 0
        label.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        label.textColor = .secondaryLabel
        contentStack.addArrangedSubview(label)
        return label
    }

    func addButton(_ title: String, action: Selector) {
        var cfg = UIButton.Configuration.tinted()
        cfg.title = title
        let btn = UIButton(configuration: cfg)
        btn.addTarget(self, action: action, for: .touchUpInside)
        contentStack.addArrangedSubview(btn)
    }

    @discardableResult
    func addTextField(_ placeholder: String, isSecure: Bool = false) -> UITextField {
        let tf = UITextField()
        tf.placeholder = placeholder
        tf.borderStyle = .roundedRect
        tf.font = .systemFont(ofSize: 14)
        tf.isSecureTextEntry = isSecure
        tf.autocapitalizationType = .none
        tf.autocorrectionType = .no
        contentStack.addArrangedSubview(tf)
        return tf
    }
}
